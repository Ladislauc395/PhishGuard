/**
 * PhishGuard Angola — background.js (Service Worker MV3)
 *
 * CORREÇÕES:
 *  - Removido "type: module" — service workers MV3 não suportam ES modules via import()
 *  - Listener movido para onCommitted (mais fiável que onBeforeNavigate para redirect)
 *  - Loop de warn/block corrigido: verificar se URL já é a página de bloqueio
 *  - Cache persistente via chrome.storage.session (sobrevive a SW restarts)
 *  - Rate limit de análise por tab para evitar spam ao backend
 */

const DEFAULT_API_BASE     = "http://10.249.221.68:8000";
const CACHE_TTL_MS         = 10 * 60 * 1000; // 10 min
const DEFAULT_BLOCK_SCORE  = 60;
const DEFAULT_WARN_SCORE   = 30;

// ─── Memória em runtime (limpa quando SW dorme) ───────────────────
// Para cache persistente usamos chrome.storage.session
const warnedTabs   = new Set();
const userApproved = new Set();
// tabId → timestamp do último pedido (throttle por tab)
const tabLastCheck = new Map();
const TAB_THROTTLE_MS = 2000; // não re-analisar a mesma tab em < 2s

// ─── Settings ────────────────────────────────────────────────────

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
    return { ...DEFAULT_SETTINGS, ...(stored.settings || {}) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

// ─── Cache via chrome.storage.session ────────────────────────────

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
  } catch {
    return null;
  }
}

async function cacheSet(url, data) {
  try {
    const key = "cache_" + btoa(url).slice(0, 80);
    await chrome.storage.session.set({ [key]: { data, ts: Date.now() } });
  } catch { /* quota exceeded — ignorar */ }
}

// ─── API call ────────────────────────────────────────────────────

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
    console.warn("[PhishGuard] API falhou para:", url, err.message);
    return {
      score:   0,
      verdict: "SEGURO",
      reasons: [],
      error:   err.message,
      offline: true,
    };
  }
}

// ─── Navegação: usar onCommitted (mais estável) ──────────────────

chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Apenas frame principal
  if (details.frameId !== 0) return;

  const { url, tabId } = details;

  // Ignorar URLs não-HTTP
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;

  // Ignorar páginas internas da extensão (block.html)
  if (url.startsWith(chrome.runtime.getURL(""))) return;

  // Ignorar localhost e o IP do backend (não analisar o próprio servidor)
  try {
    const parsed = new URL(url);
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1"
        || parsed.hostname === "10.249.221.68") return;
  } catch { return; }

  // Throttle por tab
  const lastCheck = tabLastCheck.get(tabId) || 0;
  if (Date.now() - lastCheck < TAB_THROTTLE_MS) return;
  tabLastCheck.set(tabId, Date.now());

  // URL aprovada pelo utilizador nesta sessão
  if (userApproved.has(url)) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  // Não duplicar aviso para esta tab
  if (warnedTabs.has(tabId)) {
    warnedTabs.delete(tabId); // reset para próxima navegação
    return;
  }

  let result;
  try {
    result = await checkUrl(url, settings);
  } catch (e) {
    console.error("[PhishGuard] checkUrl exception:", e);
    return;
  }

  const score = result.score ?? 0;

  await logScan(url, result);

  if (score >= settings.blockThreshold) {
    warnedTabs.add(tabId);
    await showBlockPage(tabId, url, result);
    if (settings.showNotifications) {
      showNotification("🚨 Phishing Bloqueado!", `URL perigosa: ${shortUrl(url)}`);
    }
  } else if (score >= settings.warnThreshold) {
    warnedTabs.add(tabId);
    await injectWarning(tabId, url, result);
    if (settings.showNotifications) {
      showNotification("⚠️ URL Suspeita", `${shortUrl(url)} (score ${score})`);
    }
  }
});

// ─── Bloqueio: redirigir para block.html ─────────────────────────

async function showBlockPage(tabId, url, result) {
  const params = new URLSearchParams({
    blocked_url: url,
    score:       String(result.score ?? 0),
    verdict:     result.verdict ?? "NÃO SEGURO",
    reasons:     JSON.stringify(result.reasons || []),
  });
  const blockUrl = chrome.runtime.getURL("block.html") + "?" + params.toString();
  try {
    await chrome.tabs.update(tabId, { url: blockUrl });
  } catch (e) {
    console.warn("[PhishGuard] Não foi possível redirigir tab:", e);
  }
}

// ─── Aviso: injectar overlay via content script ──────────────────

async function injectWarning(tabId, url, result) {
  // Tentar enviar mensagem ao content script já carregado
  try {
    await chrome.tabs.sendMessage(tabId, { type: "SHOW_WARNING", url, result });
    return;
  } catch { /* content script não pronto ainda */ }

  // Retry quando a tab terminar de carregar
  const listener = (id, info) => {
    if (id !== tabId || info.status !== "complete") return;
    chrome.tabs.onUpdated.removeListener(listener);
    chrome.tabs.sendMessage(tabId, { type: "SHOW_WARNING", url, result }).catch(() => {});
  };
  chrome.tabs.onUpdated.addListener(listener);
}

// ─── Logging ─────────────────────────────────────────────────────

async function logScan(url, result) {
  try {
    const stored = await chrome.storage.local.get("scanHistory");
    const history = stored.scanHistory || [];
    history.unshift({
      url,
      score:     result.score ?? 0,
      verdict:   result.verdict ?? "SEGURO",
      reasons:   result.reasons || [],
      timestamp: Date.now(),
    });
    if (history.length > 500) history.splice(500);
    await chrome.storage.local.set({ scanHistory: history });
  } catch (e) {
    console.warn("[PhishGuard] logScan falhou:", e);
  }
}

// ─── Notificações ────────────────────────────────────────────────

function showNotification(title, message) {
  chrome.notifications.create({
    type:     "basic",
    iconUrl:  "icons/icon48.png",
    title,
    message,
    priority: 2,
  });
}

// ─── Limpar estado ao fechar tab ─────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  warnedTabs.delete(tabId);
  tabLastCheck.delete(tabId);
});

// ─── Handler de mensagens (popup + content script) ───────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse).catch((err) => {
    console.error("[PhishGuard] handleMessage erro:", err);
    sendResponse({ error: String(err) });
  });
  return true; // manter canal aberto (async)
});

async function handleMessage(msg, sender) {
  const settings = await getSettings();

  switch (msg.type) {

    case "CHECK_URL": {
      if (!msg.url) return { score: 0, verdict: "SEGURO", reasons: [] };
      return await checkUrl(msg.url, settings);
    }

    case "CHECK_URLS_BATCH": {
      const urls = (msg.urls || []).slice(0, 20);
      const semaphore = { count: 0, max: 5 };

      async function limited(url) {
        // Esperar slot disponível (sem Semaphore real, usar sequencial para segurança)
        return await checkUrl(url, settings);
      }

      const entries = await Promise.all(urls.map(limited));
      const mapped = {};
      urls.forEach((u, i) => { mapped[u] = entries[i]; });
      return mapped;
    }

    case "APPROVE_URL": {
      if (msg.url) userApproved.add(msg.url);
      if (sender.tab) warnedTabs.delete(sender.tab.id);
      return { ok: true };
    }

    case "GET_HISTORY": {
      const stored = await chrome.storage.local.get("scanHistory");
      return stored.scanHistory || [];
    }

    case "GET_SETTINGS": {
      return settings;
    }

    case "SET_SETTINGS": {
      const current = await getSettings();
      await chrome.storage.sync.set({ settings: { ...current, ...msg.settings } });
      return { ok: true };
    }

    case "CLEAR_HISTORY": {
      await chrome.storage.local.set({ scanHistory: [] });
      return { ok: true };
    }

    case "CLEAR_CACHE": {
      // Limpar todas as chaves de cache da session storage
      try {
        const all = await chrome.storage.session.get(null);
        const cacheKeys = Object.keys(all).filter(k => k.startsWith("cache_"));
        if (cacheKeys.length > 0) await chrome.storage.session.remove(cacheKeys);
      } catch { /* ignorar */ }
      return { ok: true };
    }

    case "TAB_CLEARED": {
      if (msg.tabId) warnedTabs.delete(msg.tabId);
      return { ok: true };
    }

    default:
      return { error: "unknown_message_type" };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────

function shortUrl(url) {
  try {
    const u = new URL(url);
    const path = u.pathname.length > 20 ? u.pathname.slice(0, 20) + "…" : u.pathname;
    return u.hostname + path;
  } catch {
    return url.slice(0, 50);
  }
}

console.log("[PhishGuard] Service Worker iniciado ✅");
