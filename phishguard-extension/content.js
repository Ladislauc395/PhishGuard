/**
 * PhishGuard Angola — content.js
 *
 * CORREÇÕES:
 *  - MutationObserver com debounce longo (5s) para não spammar o backend
 *  - Verificação de links só corre se checkLinks estiver activo nas settings
 *  - Links já marcados não são re-enviados (controlo por Set)
 *  - Overlay não duplicado (guard por ID)
 *  - Escape HTML robusto
 */

(function () {
  "use strict";

  if (window.__phishguardInjected) return;
  window.__phishguardInjected = true;

  const SCAN_DELAY_MS  = 2500;  // aguardar DOM estabilizar
  const MAX_LINKS      = 40;    // max links a verificar por página
  const RESCAN_DELAY   = 8000;  // re-scan após mutações DOM (8s)

  // URLs já marcadas nesta página (evitar re-pedidos)
  const markedUrls = new Set();

  // ─── Estilos ────────────────────────────────────────────────────

  function injectStyles() {
    if (document.getElementById("pg-styles")) return;
    const s = document.createElement("style");
    s.id = "pg-styles";
    s.textContent = `
      #pg-overlay {
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(15,10,30,0.97);
        display: flex; align-items: center; justify-content: center;
        font-family: 'Segoe UI', system-ui, sans-serif;
        animation: pg-fadein 0.25s ease;
      }
      @keyframes pg-fadein {
        from { opacity:0; transform:translateY(-12px); }
        to   { opacity:1; transform:translateY(0); }
      }
      #pg-card {
        background:#1a1030; border:2px solid #ff3b3b; border-radius:16px;
        padding:36px 40px; max-width:520px; width:90%; text-align:center;
        box-shadow:0 0 60px rgba(255,59,59,.3),0 24px 48px rgba(0,0,0,.6);
      }
      #pg-card .pg-icon { font-size:60px; margin-bottom:8px; display:block; }
      #pg-card h2 { color:#ff3b3b; font-size:24px; margin:0 0 8px; font-weight:700; }
      #pg-card .pg-subtitle { color:#c0b8d8; font-size:13px; margin:0 0 18px; line-height:1.5; }
      #pg-score-bar {
        background:#2a1f45; border-radius:8px; padding:12px 16px; margin-bottom:16px;
        display:flex; align-items:center; gap:14px; text-align:left;
      }
      #pg-score-num { font-size:38px; font-weight:800; color:#ff3b3b; min-width:54px; line-height:1; }
      #pg-score-label .label { color:#f0eaff; font-weight:600; font-size:13px; }
      #pg-score-label .verdict { color:#ff3b3b; font-size:11px; text-transform:uppercase; letter-spacing:1px; margin-top:2px; }
      #pg-reasons {
        background:#120d25; border-radius:8px; padding:10px 14px; margin-bottom:18px;
        text-align:left; max-height:120px; overflow-y:auto;
      }
      #pg-reasons p { color:#e8dfff; font-size:12px; margin:0 0 5px; line-height:1.5; padding-left:16px; position:relative; }
      #pg-reasons p::before { content:"⚠"; position:absolute; left:0; color:#ff9a3b; }
      #pg-url { color:#7b6ea0; font-size:10px; word-break:break-all; margin-bottom:20px; font-family:monospace; }
      .pg-btn {
        display:inline-block; padding:11px 24px; border-radius:10px;
        font-size:13px; font-weight:600; cursor:pointer; border:none; margin:0 5px;
        transition:transform .1s;
      }
      .pg-btn:hover { transform:translateY(-1px); }
      .pg-btn-back { background:linear-gradient(135deg,#6c3fc7,#4a1fa8); color:#fff; }
      .pg-btn-proceed { background:transparent; color:#7b6ea0; border:1px solid #3a2c5a; font-size:11px; padding:9px 16px; }
      .pg-btn-proceed:hover { color:#ff3b3b; border-color:#ff3b3b; }
      .pg-powered { color:#3a2c5a; font-size:10px; margin-top:16px; }
      .pg-link-badge {
        display:inline-block; background:#ff3b3b; color:#fff;
        font-size:10px; font-weight:700; padding:1px 5px; border-radius:4px;
        margin-left:4px; vertical-align:middle; cursor:help;
        font-family:system-ui,sans-serif; letter-spacing:.3px;
      }
      .pg-link-badge.pg-warn { background:#e67e00; }
      a.pg-phishing-link  { outline:2px solid #ff3b3b !important; outline-offset:2px; border-radius:3px; }
      a.pg-suspicious-link { outline:2px solid #e67e00 !important; outline-offset:2px; border-radius:3px; }
    `;
    (document.head || document.documentElement).appendChild(s);
  }

  // ─── Overlay de aviso ───────────────────────────────────────────

  function showWarningOverlay(url, result) {
    injectStyles();
    if (document.getElementById("pg-overlay")) return;

    const score   = result.score   ?? 0;
    const verdict = result.verdict ?? "SUSPEITO";
    const reasons = result.reasons ?? [];
    const isBlock = score >= 60;

    const overlay = document.createElement("div");
    overlay.id = "pg-overlay";

    const reasonsHtml = reasons.slice(0, 5).map(r => `<p>${escHtml(r)}</p>`).join("")
      || "<p>Padrões de phishing detectados nesta página.</p>";

    overlay.innerHTML = `
      <div id="pg-card">
        <span class="pg-icon">${isBlock ? "🚫" : "⚠️"}</span>
        <h2>${isBlock ? "Phishing Detectado!" : "Página Suspeita"}</h2>
        <p class="pg-subtitle">
          ${isBlock
            ? "Esta página foi identificada como phishing — pode roubar credenciais ou dados bancários."
            : "Esta página apresenta sinais suspeitos. Proceda com extremo cuidado."}
        </p>
        <div id="pg-score-bar">
          <div id="pg-score-num">${score}</div>
          <div id="pg-score-label">
            <div class="label">Pontuação de Risco</div>
            <div class="verdict">${escHtml(verdict)}</div>
          </div>
        </div>
        <div id="pg-reasons">${reasonsHtml}</div>
        <div id="pg-url">${escHtml(url)}</div>
        <div>
          <button class="pg-btn pg-btn-back" id="pg-btn-back">← Voltar para segurança</button>
          <button class="pg-btn pg-btn-proceed" id="pg-btn-proceed">Ignorar aviso (risco)</button>
        </div>
        <div class="pg-powered">Protegido por PhishGuard Angola</div>
      </div>
    `;

    (document.body || document.documentElement).appendChild(overlay);

    document.getElementById("pg-btn-back").addEventListener("click", () => {
      if (window.history.length > 1) window.history.back();
      else window.location.href = "https://www.google.com";
      overlay.remove();
    });

    document.getElementById("pg-btn-proceed").addEventListener("click", () => {
      overlay.remove();
      try {
        chrome.runtime.sendMessage({ type: "APPROVE_URL", url });
      } catch { /* SW pode ter adormecido */ }
    });
  }

  // ─── Scan de links ──────────────────────────────────────────────

  let linkScanTimer = null;
  let scanPending   = false;

  function scheduleLinkScan() {
    if (scanPending) return;
    clearTimeout(linkScanTimer);
    linkScanTimer = setTimeout(runLinkScan, SCAN_DELAY_MS);
  }

  async function runLinkScan() {
    scanPending = true;
    try {
      await doScanLinks();
    } finally {
      scanPending = false;
    }
  }

  async function doScanLinks() {
    // Verificar se opção está activa
    let settings = {};
    try {
      settings = await sendMsg("GET_SETTINGS") || {};
    } catch { return; }

    if (settings.checkLinks === false) return;

    const anchors = [...document.querySelectorAll("a[href]")]
      .filter(a => {
        const h = a.href;
        return (h.startsWith("http://") || h.startsWith("https://"))
          && !markedUrls.has(a.href);
      })
      .slice(0, MAX_LINKS);

    if (anchors.length === 0) return;

    const urls = [...new Set(anchors.map(a => a.href))];

    let results;
    try {
      results = await sendMsg("CHECK_URLS_BATCH", { urls });
    } catch { return; }

    if (!results) return;

    for (const a of anchors) {
      const r = results[a.href];
      if (!r) continue;

      markedUrls.add(a.href); // não re-verificar

      const score = r.score ?? 0;
      if (score >= 60) {
        a.classList.add("pg-phishing-link");
        if (!a.querySelector(".pg-link-badge")) {
          const b = document.createElement("span");
          b.className = "pg-link-badge";
          b.textContent = "PHISHING";
          b.title = `Score: ${score}\n${(r.reasons || []).slice(0, 3).join("\n")}`;
          a.appendChild(b);
        }
      } else if (score >= 30) {
        a.classList.add("pg-suspicious-link");
        if (!a.querySelector(".pg-link-badge")) {
          const b = document.createElement("span");
          b.className = "pg-link-badge pg-warn";
          b.textContent = "SUSPEITO";
          b.title = `Score: ${score}\n${(r.reasons || []).slice(0, 3).join("\n")}`;
          a.appendChild(b);
        }
      }
    }
  }

  // ─── Listener de mensagens ──────────────────────────────────────

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SHOW_WARNING") {
      showWarningOverlay(msg.url, msg.result);
    }
  });

  // ─── Iniciar scan quando página carrega ─────────────────────────

  if (document.readyState === "complete" || document.readyState === "interactive") {
    scheduleLinkScan();
  } else {
    document.addEventListener("DOMContentLoaded", scheduleLinkScan, { once: true });
  }

  // Re-scan em SPAs — debounce longo para não spammar
  let mutationDebounce = null;
  const observer = new MutationObserver(() => {
    clearTimeout(mutationDebounce);
    mutationDebounce = setTimeout(scheduleLinkScan, RESCAN_DELAY);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // ─── Helpers ────────────────────────────────────────────────────

  function escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function sendMsg(type, extra = {}) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type, ...extra }, (resp) => {
          if (chrome.runtime.lastError) resolve(null);
          else resolve(resp);
        });
      } catch {
        resolve(null);
      }
    });
  }

})();