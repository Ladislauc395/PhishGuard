/**
 * PhishGuard Angola — background.js (Service Worker MV3)
 */
const DEFAULT_API_BASE     = "http://10.249.221.68:8000";
const CACHE_TTL_MS         = 10 * 60 * 1000;
const DEFAULT_BLOCK_SCORE  = 60;
const DEFAULT_WARN_SCORE   = 30;

const warnedTabs   = new Set();
const userApproved = new Set();
const tabLastCheck = new Map();
const TAB_THROTTLE_MS = 2000;

const DEFAULT_SETTINGS = {
  enabled:           true,
  blockThreshold:    DEFAULT_BLOCK_SCORE,
  warnThreshold:     DEFAULT_WARN_SCORE,
  apiBase:           DEFAULT_API_BASE,
  showNotifications: true,
  checkLinks:        true,
};

async function getSettings() {
  try {
    const stored = await chrome.storage.sync.get("settings");
    const merged = { ...DEFAULT_SETTINGS, ...(stored.settings || {}) };
    if (!merged.apiBase || merged.apiBase.trim() === "") {
      merged.apiBase = DEFAULT_API_BASE;
    }
    return merged;
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

async function cacheGet(url) {
  try {
    const key = "cache_" + btoa(url).slice(0, 80);
    const res = await chrome.storage.session.get(key);
    const entry = res[key];
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL_MS) {
      chrome.storage.session.remove(key);
      return null;
    }
    return entry.data;
  } catch { return null; }
}

async function cacheSet(url, data) {
  try {
    const key = "cache_" + btoa(url).slice(0, 80);
    await chrome.storage.session.set({ [key]: { data, ts: Date.now() } });
  } catch {}
}

async function clearAllCache() {
  try {
    const all = await chrome.storage.session.get(null);
    const cacheKeys = Object.keys(all).filter(k => k.startsWith("cache_"));
    if (cacheKeys.length > 0) await chrome.storage.session.remove(cacheKeys);
  } catch {}
}

async function checkUrl(url, settings) {
  const cached = await cacheGet(url);
  if (cached) return { ...cached, cached: true };

  const apiBase = (settings && settings.apiBase) || DEFAULT_API_BASE;

  try {
    const resp = await fetch(`${apiBase}/extension/check-url`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  AbortSignal.timeout(12000),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const result = await resp.json();
    await cacheSet(url, result);
    return result;
  } catch (err) {
    console.warn("[PhishGuard] API falhou:", err.message);
    return { score: 0, verdict: "SEGURO", reasons: [], error: err.message, offline: true };
  }
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { url, tabId } = details;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;
  if (url.startsWith(chrome.runtime.getURL(""))) return;
  try {
    const parsed = new URL(url);
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1"
        || parsed.hostname === "10.249.221.68" || parsed.hostname === "10.249.221.68") return;
  } catch { return; }

  const lastCheck = tabLastCheck.get(tabId) || 0;
  if (Date.now() - lastCheck < TAB_THROTTLE_MS) return;
  tabLastCheck.set(tabId, Date.now());

  if (userApproved.has(url)) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  if (warnedTabs.has(tabId)) { warnedTabs.delete(tabId); return; }

  let result;
  try { result = await checkUrl(url, settings); } catch (e) { return; }

  const score = result.score ?? 0;
  await logScan(url, result);

  if (score >= settings.blockThreshold) {
    warnedTabs.add(tabId);
    await showBlockPage(tabId, url, result);
    if (settings.showNotifications) showNotification("🚨 Phishing Bloqueado!", `URL: ${shortUrl(url)}`);
  } else if (score >= settings.warnThreshold) {
    warnedTabs.add(tabId);
    await injectWarning(tabId, url, result);
    if (settings.showNotifications) showNotification("⚠️ URL Suspeita", `${shortUrl(url)} (${score})`);
  }
});

async function showBlockPage(tabId, url, result) {
  const params = new URLSearchParams({
    blocked_url: url, score: String(result.score ?? 0),
    verdict: result.verdict ?? "NÃO SEGURO", reasons: JSON.stringify(result.reasons || []),
  });
  try { await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("block.html") + "?" + params.toString() }); } catch {}
}

async function injectWarning(tabId, url, result) {
  try { await chrome.tabs.sendMessage(tabId, { type: "SHOW_WARNING", url, result }); return; } catch {}
  const listener = (id, info) => {
    if (id !== tabId || info.status !== "complete") return;
    chrome.tabs.onUpdated.removeListener(listener);
    chrome.tabs.sendMessage(tabId, { type: "SHOW_WARNING", url, result }).catch(() => {});
  };
  chrome.tabs.onUpdated.addListener(listener);
}

async function logScan(url, result) {
  try {
    const stored = await chrome.storage.local.get("scanHistory");
    const history = stored.scanHistory || [];
    history.unshift({ url, score: result.score ?? 0, verdict: result.verdict ?? "SEGURO", reasons: result.reasons || [], timestamp: Date.now() });
    if (history.length > 500) history.splice(500);
    await chrome.storage.local.set({ scanHistory: history });
  } catch {}
}

function showNotification(title, message) {
  chrome.notifications.create({ type: "basic", iconUrl: "icons/icon48.png", title, message, priority: 2 });
}

chrome.tabs.onRemoved.addListener((tabId) => { warnedTabs.delete(tabId); tabLastCheck.delete(tabId); });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch(err => sendResponse({ error: String(err) }));
  return true;
});

async function handleMessage(msg, sender) {
  const settings = await getSettings();
  switch (msg.type) {
    case "CHECK_URL": return msg.url ? await checkUrl(msg.url, settings) : { score: 0, verdict: "SEGURO", reasons: [] };
    case "CHECK_URLS_BATCH": {
      const urls = (msg.urls || []).slice(0, 20);
      const entries = await Promise.all(urls.map(u => checkUrl(u, settings)));
      const mapped = {}; urls.forEach((u, i) => { mapped[u] = entries[i]; });
      return mapped;
    }
    case "APPROVE_URL": if (msg.url) userApproved.add(msg.url); if (sender.tab) warnedTabs.delete(sender.tab.id); return { ok: true };
    case "GET_HISTORY": { const stored = await chrome.storage.local.get("scanHistory"); return stored.scanHistory || []; }
    case "GET_SETTINGS": return settings;
    case "SET_SETTINGS": {
      const current = await getSettings();
      const newSettings = { ...current, ...msg.settings };
      if (!newSettings.apiBase || newSettings.apiBase.trim() === "") newSettings.apiBase = DEFAULT_API_BASE;
      await chrome.storage.sync.set({ settings: newSettings });
      await clearAllCache();
      return { ok: true };
    }
    case "CLEAR_HISTORY": await chrome.storage.local.set({ scanHistory: [] }); return { ok: true };
    case "CLEAR_CACHE": await clearAllCache(); return { ok: true };
    case "TAB_CLEARED": if (msg.tabId) warnedTabs.delete(msg.tabId); return { ok: true };
    default: return { error: "unknown_message_type" };
  }
}

function shortUrl(url) {
  try { const u = new URL(url); return u.hostname + (u.pathname.length > 20 ? u.pathname.slice(0, 20) + "…" : u.pathname); }
  catch { return url.slice(0, 50); }
}

console.log("[PhishGuard] Service Worker iniciado ✅ — API:", DEFAULT_API_BASE);


