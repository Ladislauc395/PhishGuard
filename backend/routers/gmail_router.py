"""
backend/routers/gmail_router.py
────────────────────────────────
Endpoints FastAPI para o Gmail PhishGuard.

CORRECÇÕES v9:
  - GET /auth/gmail/status: inclui diagnóstico detalhado
  - GET /gmail/emails/all: resposta sempre imediata
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from backend.services.gmail_hook import (
    exchange_code_for_tokens,
    get_all_analysed_emails,
    get_blocked_emails_async,
    get_gmail_auth_url,
    get_gmail_diagnostics,
    is_gmail_connected,
    is_scan_running,
    scan_inbox,
    unblock_email_async,
    force_refresh,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["gmail"])


# ─── OAuth2 ──────────────────────────────────────────────────────

@router.get("/auth/gmail/url")
async def gmail_auth_url() -> Dict[str, str]:
    try:
        url = get_gmail_auth_url()
        return {"auth_url": url}
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.get("/auth/gmail/callback")
async def gmail_callback(
    code:  str           = Query(...),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
) -> HTMLResponse:
    if error:
        return HTMLResponse(
            content=_html_result(
                "Autorização Negada",
                f"O acesso ao Gmail foi negado: {error}",
                success=False,
            ),
            status_code=400,
        )

    try:
        tokens = await exchange_code_for_tokens(code)
        if not tokens.get("refresh_token") and not tokens.get("access_token"):
            raise ValueError("Tokens não recebidos")
    except Exception as exc:
        logger.error("OAuth callback falhou: %s", exc)
        return HTMLResponse(
            content=_html_result(
                "Erro na Autorização",
                f"Não foi possível completar a autorização: {exc}",
                success=False,
            ),
            status_code=500,
        )

    return HTMLResponse(
        content=_html_result(
            "Gmail Conectado! ✓",
            "O PhishGuard está agora a monitorar o seu Gmail. "
            "Pode fechar este separador e voltar à aplicação.",
            success=True,
        )
    )


@router.get("/auth/gmail/status")
async def gmail_status() -> Dict[str, Any]:
    """Estado do Gmail com diagnóstico detalhado."""
    connected = is_gmail_connected()
    diag = get_gmail_diagnostics()
    return {
        "gmail_connected":       connected,
        "gmail_monitor_running": False,
        "last_scan_at":          None,
        "diagnostics":           diag,
    }


# ─── Emails ──────────────────────────────────────────────────────

@router.get("/gmail/emails/all")
async def get_all_emails(max_results: int = Query(100, ge=1, le=200)) -> Dict:
    """
    Devolve TODOS os emails analisados nesta sessão.
    Resposta SEMPRE imediata.
    """
    if not is_gmail_connected():
        raise HTTPException(status_code=403, detail="Gmail não conectado")
    try:
        emails = await get_all_analysed_emails(max_results)
        return {
            "emails":   emails,
            "total":    len(emails),
            "scanning": is_scan_running(),
        }
    except Exception as exc:
        logger.error("get_all_emails falhou: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/gmail/emails/blocked")
async def get_blocked(max_results: int = Query(50, ge=1, le=100)) -> List[Dict]:
    if not is_gmail_connected():
        raise HTTPException(status_code=403, detail="Gmail não conectado")
    try:
        return await get_blocked_emails_async(max_results)
    except Exception as exc:
        logger.error("get_blocked_emails falhou: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/gmail/scan")
async def trigger_scan(
    max_results: int  = Query(20, ge=1, le=50),
    auto_block:  bool = Query(True),
) -> Dict[str, Any]:
    """Dispara um scan imediato da caixa de entrada."""
    if not is_gmail_connected():
        raise HTTPException(status_code=403, detail="Gmail não conectado")
    try:
        results       = await scan_inbox(max_results=max_results, auto_block=auto_block)
        scanned       = len(results)
        threats_found = sum(1 for r in results if r.get("analysis", {}).get("score", 0) >= 70)
        auto_blocked  = sum(1 for r in results if r.get("analysis", {}).get("blocked"))
        return {
            "scanned":       scanned,
            "threats_found": threats_found,
            "auto_blocked":  auto_blocked,
            "results":       results,
        }
    except Exception as exc:
        logger.error("trigger_scan falhou: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/gmail/scan/refresh")
async def force_scan_refresh(
    max_results: int = Query(30, ge=1, le=100),
) -> Dict[str, Any]:
    """Força um scan completo e aguarda o resultado."""
    if not is_gmail_connected():
        raise HTTPException(status_code=403, detail="Gmail não conectado")
    try:
        emails = await force_refresh(max_results=max_results)
        threats_found = sum(
            1 for e in emails
            if e.get("analysis", {}).get("score", 0) >= 60
        )
        return {
            "total":         len(emails),
            "threats_found": threats_found,
            "emails":        emails,
            "scanning":      False,
        }
    except Exception as exc:
        logger.error("force_scan_refresh falhou: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/gmail/unblock/{message_id}")
async def unblock_email(message_id: str) -> Dict[str, Any]:
    if not is_gmail_connected():
        raise HTTPException(status_code=403, detail="Gmail não conectado")
    try:
        ok = await unblock_email_async(message_id)
        if not ok:
            raise HTTPException(status_code=500, detail="Não foi possível restaurar o email")
        return {"success": True, "message_id": message_id}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("unblock_email falhou para %s: %s", message_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ─── Helpers HTML ─────────────────────────────────────────────────

def _html_result(title: str, message: str, success: bool = True) -> str:
    color = "#16a34a" if success else "#dc2626"
    icon  = "✓" if success else "✗"
    return f"""<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PhishGuard — {title}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; margin: 0;
      background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
      color: white;
    }}
    .card {{
      background: rgba(255,255,255,0.1);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      padding: 40px;
      text-align: center;
      max-width: 400px;
    }}
    .icon {{
      font-size: 64px;
      width: 90px; height: 90px;
      background: {color};
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 20px;
    }}
    h1 {{ margin: 0 0 12px; font-size: 22px; }}
    p  {{ margin: 0; opacity: 0.85; line-height: 1.5; font-size: 14px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">{icon}</div>
    <h1>{title}</h1>
    <p>{message}</p>
  </div>
</body>
</html>"""
