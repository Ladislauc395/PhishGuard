/**
 * PhishGuard Angola — popup.js
 *
 * CORREÇÕES:
 *  - URL padrão da API alterada para http://10.249.221.68:8000
 *  - checkApiStatus aponta para /extension/health
 *  - sendMsg com timeout para evitar popup a travar
 *  - loadHistory mostra stats correctamente
 *  - checkCurrentTab ignora URLs de extensão e chrome://
 */

const DEFAULT_API_BASE = "http://10.249.221.68:8000";

document.addEventListener("DOMContentLoaded", async () => {
  setupTabs();
  setupToggle();
  setupScanButton();
  await Promise.all([
    loadSettings(),
    loadHistory(),
    checkCurrentTab(),
    checkApiStatus(),
  ]);
});

// ─── Settings ────────────────────────────────────────────────────

async function loadSettings() {
  const s = await sendMsg("GET_SETTINGS");
  if (!s) return;

  safeSet("toggle-enabled",      el => el.checked = s.enabled !== false);
  safeSet("s-auto-block",        el => el.checked = (s.blockThreshold || 60) <= 80);
  safeSet("s-block-threshold",   el => el.value   = s.blockThreshold || 60);
  safeSet("s-warn-threshold",    el => el.value   = s.warnThreshold  || 30);
  safeSet("s-check-links",       el => el.checked = s.checkLinks !== false);
  safeSet("s-notifications",     el => el.checked = s.showNotifications !== false);
  // CORRIGIDO: fallback para IP real em vez de localhost
  safeSet("s-api-url",           el => el.value   = s.apiBase || DEFAULT_API_BASE);
}

window.saveSettings = async function () {
  const settings = {
    enabled:           document.getElementById("toggle-enabled").checked,
    blockThreshold:    parseInt(document.getElementById("s-block-threshold").value, 10) || 60,
    warnThreshold:     parseInt(document.getElementById("s-warn-threshold").value,  10) || 30,
    checkLinks:        document.getElementById("s-check-links").checked,
    showNotifications: document.getElementById("s-notifications").checked,
    // CORRIGIDO: fallback para IP real em vez de localhost
    apiBase:           (document.getElementById("s-api-url").value || "").trim() || DEFAULT_API_BASE,
  };
  await sendMsg("SET_SETTINGS", { settings });
  showToast("✅ Definições guardadas!");
};

window.clearHistory = async function () {
  if (!confirm("Limpar todo o histórico de verificações?")) return;
  await sendMsg("CLEAR_HISTORY");
  await sendMsg("CLEAR_CACHE");
  const list = document.getElementById("history-list");
  if (list) list.innerHTML = '<div style="color:#3a2c5a;font-size:12px;padding:10px 0;text-align:center;">Histórico limpo</div>';
  safeSet("stat-total", el => el.textContent = "0");
  safeSet("stat-warn",  el => el.textContent = "0");
  safeSet("stat-block", el => el.textContent = "0");
};

window.openDashboard = function () {
  // CORRIGIDO: fallback para IP real em vez de localhost
  const apiBase = (document.getElementById("s-api-url")?.value || DEFAULT_API_BASE).trim();
  chrome.tabs.create({ url: apiBase + "/docs" });
};

// ─── Toggle ──────────────────────────────────────────────────────

function setupToggle() {
  const tog = document.getElementById("toggle-enabled");
  if (!tog) return;
  tog.addEventListener("change", async (e) => {
    await sendMsg("SET_SETTINGS", { settings: { enabled: e.target.checked } });
  });
}

// ─── Verificar tab actual ────────────────────────────────────────

async function checkCurrentTab() {
  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch { return; }

  if (!tab?.url) return;

  const url = tab.url;

  // Ignorar páginas internas
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
      url.startsWith("about:") || url.startsWith("edge://")) {
    setCurrentUrl(url);
    setStatus("safe", "Página interna do browser", "–", "");
    return;
  }

  setCurrentUrl(url);
  setStatus("loading", "A verificar…", "–", "");

  const result = await sendMsg("CHECK_URL", { url });
  if (!result) {
    setStatus("safe", "API indisponível", "–", "offline");
    return;
  }

  const score   = result.score   ?? 0;
  const verdict = result.verdict ?? "SEGURO";

  const cls   = score >= 60 ? "danger" : score >= 30 ? "warn" : "safe";
  const label = score >= 60 ? "🚨 " + verdict : score >= 30 ? "⚠️ " + verdict : "✅ " + verdict;

  setStatus(cls, label, score, "");

  const box = document.getElementById("reasons-mini");
  if (box && result.reasons && result.reasons.length > 0) {
    box.style.display = "block";
    box.innerHTML = result.reasons.slice(0, 4).map(r =>
      `<div class="reason-mini-item">${escHtml(r)}</div>`
    ).join("");
  }
}

function setupScanButton() {
  const btn = document.getElementById("btn-scan");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "🔄 A verificar…";
    await checkCurrentTab();
    btn.disabled = false;
    btn.textContent = "🔍 Verificar Agora";
  });
}

// ─── Histórico ───────────────────────────────────────────────────

async function loadHistory() {
  const history = await sendMsg("GET_HISTORY") || [];

  const total   = history.length;
  const blocked = history.filter(h => (h.score || 0) >= 60).length;
  const warned  = history.filter(h => (h.score || 0) >= 30 && (h.score || 0) < 60).length;

  safeSet("stat-total", el => el.textContent = total);
  safeSet("stat-block", el => el.textContent = blocked);
  safeSet("stat-warn",  el => el.textContent = warned);

  const list = document.getElementById("history-list");
  if (!list) return;

  if (history.length === 0) {
    list.innerHTML = '<div style="color:#3a2c5a;font-size:12px;padding:10px 0;text-align:center;">Sem histórico ainda</div>';
    return;
  }

  list.innerHTML = history.slice(0, 30).map(h => {
    const score = h.score || 0;
    const cls = score >= 60 ? "danger" : score >= 30 ? "warn" : "safe";
    return `
      <div class="history-item" title="${escHtml(h.url || '')}">
        <div class="history-dot ${cls}"></div>
        <div class="history-url">${escHtml(shortUrl(h.url || ''))}</div>
        <div class="history-score ${cls}">${score}</div>
      </div>
    `;
  }).join("");
}

// ─── Status da API ────────────────────────────────────────────────

async function checkApiStatus() {
  const settings = await sendMsg("GET_SETTINGS");
  // CORRIGIDO: fallback para IP real em vez de localhost
  const apiBase  = (settings?.apiBase || DEFAULT_API_BASE).trim();
  const dot      = document.getElementById("api-dot");
  const txt      = document.getElementById("api-status-text");
  if (!dot || !txt) return;

  try {
    const r = await fetch(`${apiBase}/extension/health`, {
      signal: AbortSignal.timeout(4000),
    });
    if (r.ok) {
      dot.classList.remove("offline");
      dot.classList.add("online");
      txt.textContent = "API online";
    } else {
      throw new Error(`HTTP ${r.status}`);
    }
  } catch {
    dot.classList.remove("online");
    dot.classList.add("offline");
    txt.textContent = "API offline";
  }
}

// ─── Tabs ─────────────────────────────────────────────────────────

function setupTabs() {
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      const id = tab.dataset.tab;
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));
      tab.classList.add("active");
      const content = document.getElementById(`tab-${id}`);
      if (content) content.classList.add("active");
    });
  });
}

// ─── Helpers ─────────────────────────────────────────────────────

function safeSet(id, fn) {
  const el = document.getElementById(id);
  if (el) fn(el);
}

function setCurrentUrl(url) {
  const el = document.getElementById("current-url");
  if (!el) return;
  try {
    const u = new URL(url);
    el.textContent = u.hostname + (u.pathname.length > 30 ? u.pathname.slice(0, 30) + "…" : u.pathname);
  } catch {
    el.textContent = url.slice(0, 50);
  }
}

function setStatus(cls, text, score, _extra) {
  safeSet("status-dot",  el => { el.className = `status-dot ${cls}`; });
  safeSet("status-text", el => { el.className = `status-text ${cls}`; el.textContent = text; });
  safeSet("score-badge", el => { el.className = `score-badge ${cls}`; el.textContent = score; });
}

function shortUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname.length > 18 ? u.pathname.slice(0, 18) + "…" : u.pathname);
  } catch {
    return String(url).slice(0, 40);
  }
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function showToast(msg) {
  const t = document.createElement("div");
  t.style.cssText = [
    "position:fixed", "bottom:14px", "left:50%", "transform:translateX(-50%)",
    "background:#4a1fa8", "color:#fff", "padding:7px 18px", "border-radius:20px",
    "font-size:12px", "font-weight:600", "z-index:9999", "pointer-events:none",
  ].join(";");
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2000);
}

// sendMsg com timeout de 8s para não travar o popup
function sendMsg(type, extra = {}) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), 8000);
    try {
      chrome.runtime.sendMessage({ type, ...extra }, (resp) => {
        clearTimeout(timer);
        if (chrome.runtime.lastError) resolve(null);
        else resolve(resp);
      });
    } catch {
      clearTimeout(timer);
      resolve(null);
    }
  });
}