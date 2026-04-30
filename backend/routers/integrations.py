"""Endpoints para gerir integrações (Gmail, SMS, Extensão)."""
from __future__ import annotations
import asyncio
import base64
import logging
from datetime import datetime, timezone
from typing import Optional
from email import message_from_bytes
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from backend.core.config import settings
from backend.core.database import get_session, engine
from backend.models.analysis import Analysis
from backend.services.orchestrator import orchestrate_email

# importações do gmail_hook (nomes reais das funções async)
from backend.services.gmail_hook import (
    scan_inbox,
    block_email_async,
    unblock_email_async,
    get_blocked_emails_async,
    _get_access_token_async,
    _get_or_create_blocked_label,
    _auth_headers,
    GMAIL_API_BASE,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations", tags=["integrations"])


# ─────────────────────────────────────────────────────────────────
# Modelos
# ─────────────────────────────────────────────────────────────────

class IntegrationStatus(BaseModel):
    gmail_connected: bool
    gmail_email: Optional[str] = None
    sms_monitor_enabled: bool
    gmail_monitor_running: bool
    last_scan_at: Optional[str] = None
    last_scan_threats: int = 0
    extension_url: str


class ScanResult(BaseModel):
    scanned: int
    threats_found: int
    analyses_ids: list[int]


# Modelo v4 (suporta auto_blocked + results)
class ScanResultV4(BaseModel):
    scanned: int
    threats_found: int
    auto_blocked: int
    results: list


class BlockRequest(BaseModel):
    message_id: str
    reasons: list[str] = []
    score: int = 100


# ─────────────────────────────────────────────────────────────────
# Estado global (em produção → Redis / tabela settings)
# ─────────────────────────────────────────────────────────────────

_state = {
    "gmail_connected": False,
    "gmail_email": None,
    "sms_enabled": False,
    "gmail_monitor_running": False,
    "last_scan_at": None,
    "last_scan_threats": 0,
    "seen_ids": set(),
}
_monitor_task: Optional[asyncio.Task] = None


# ─────────────────────────────────────────────────────────────────
# Credentials helpers — originais
# ─────────────────────────────────────────────────────────────────

def _gmail_creds() -> Credentials:
    creds = Credentials(
        token=None,
        refresh_token=settings.GMAIL_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GMAIL_CLIENT_ID,
        client_secret=settings.GMAIL_CLIENT_SECRET,
    )
    # Request() usa requests (síncrono) — só chamar dentro de to_thread()
    creds.refresh(Request())
    return creds


def _gmail_service():
    return build("gmail", "v1", credentials=_gmail_creds(), cache_discovery=False)


def _extract_body(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    continue
    else:
        try:
            return msg.get_payload(decode=True).decode(errors="ignore")
        except Exception:
            return ""
    return ""


def _fetch_messages_sync(max_results: int, unread_only: bool = True):
    """Tudo síncrono (Google SDK) — retorna lista de dicts prontos para análise."""
    svc = _gmail_service()
    q = "is:unread" if unread_only else ""
    listing = svc.users().messages().list(
        userId="me", maxResults=max_results, q=q
    ).execute()

    out = []
    for item in listing.get("messages", []):
        mid = item["id"]
        msg = svc.users().messages().get(
            userId="me", id=mid, format="raw"
        ).execute()
        raw = base64.urlsafe_b64decode(msg["raw"])
        parsed = message_from_bytes(raw)
        out.append({
            "id": mid,
            "sender": parsed.get("From", "unknown@unknown.com"),
            "subject": parsed.get("Subject", ""),
            "headers": "\n".join(f"{k}: {v}" for k, v in parsed.items()),
            "body": _extract_body(parsed),
        })
    return out


# ─────────────────────────────────────────────────────────────────
# Lógica partilhada de scan (usada pelos endpoints GET e POST)
# ─────────────────────────────────────────────────────────────────

async def _run_scan_legacy(max_results: int) -> ScanResult:
    """Pipeline original — preservado para retrocompatibilidade com POST."""
    if not _state["gmail_connected"]:
        raise HTTPException(400, "Gmail não conectado")

    try:
        messages = await asyncio.to_thread(_fetch_messages_sync, max_results, True)
    except Exception as e:
        logger.exception("Erro ao ler Gmail")
        raise HTTPException(500, f"Gmail read failed: {e}")

    threats = 0
    ids: list[int] = []

    with Session(engine) as session:
        for m in messages:
            try:
                result = await orchestrate_email(m["sender"], m["headers"], m["body"])
                a = Analysis(
                    channel="email",
                    score=result["score"],
                    verdict=result["verdict"],
                    details=result,
                )
                session.add(a)
                session.commit()
                session.refresh(a)
                ids.append(a.id)
                if result["score"] >= 60:
                    threats += 1
                _state["seen_ids"].add(m["id"])
            except Exception as e:
                logger.warning("Falha analisar msg %s: %s", m["id"], e)

    _state["last_scan_at"] = datetime.now(timezone.utc).isoformat()
    _state["last_scan_threats"] = threats
    return ScanResult(scanned=len(ids), threats_found=threats, analyses_ids=ids)


async def _run_scan_v4(max_results: int, auto_block: bool) -> ScanResultV4:
    """Pipeline async v4 — análise em paralelo, sem bloquear o worker."""
    try:
        results = await scan_inbox(
            max_results=max_results,
            query="is:unread",
            auto_block=auto_block,
        )
        threats = sum(1 for r in results if r.get("analysis", {}).get("score", 0) >= 60)
        blocked = sum(1 for r in results if r.get("analysis", {}).get("blocked", False))

        _state["last_scan_at"] = datetime.now(timezone.utc).isoformat()
        _state["last_scan_threats"] = threats

        return ScanResultV4(
            scanned=len(results),
            threats_found=threats,
            auto_blocked=blocked,
            results=results,
        )
    except Exception as e:
        logger.exception("_run_scan_v4 falhou")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────
# Endpoints — status e Gmail connect/disconnect (originais)
# ─────────────────────────────────────────────────────────────────

@router.get("/status", response_model=IntegrationStatus)
async def status():
    return IntegrationStatus(
        gmail_connected=_state["gmail_connected"],
        gmail_email=_state["gmail_email"],
        sms_monitor_enabled=_state["sms_enabled"],
        gmail_monitor_running=_state["gmail_monitor_running"],
        last_scan_at=_state["last_scan_at"],
        last_scan_threats=_state["last_scan_threats"],
        extension_url="http://localhost:8000/integrations/extension/download",
    )


@router.post("/gmail/connect")
async def gmail_connect():
    """
    Conecta ao Gmail via OAuth2.

    CORRECÇÃO: _gmail_service() usa o Google SDK síncrono (requests bloqueante).
    Envolto em asyncio.to_thread() para não bloquear o event loop do FastAPI
    e evitar o TimeoutException no cliente Flutter (timeout 30 s).
    """
    def _connect_sync():
        svc = _gmail_service()
        profile = svc.users().getProfile(userId="me").execute()
        return profile.get("emailAddress")

    try:
        email = await asyncio.wait_for(
            asyncio.to_thread(_connect_sync),
            timeout=25.0,  # margem antes do timeout de 30 s do Flutter
        )
        _state["gmail_connected"] = True
        _state["gmail_email"] = email
        return {"ok": True, "email": email}
    except asyncio.TimeoutError:
        logger.error("gmail_connect: timeout ao contactar a Google API")
        raise HTTPException(504, "Timeout ao conectar ao Gmail. Verifique a ligação e tente de novo.")
    except Exception as e:
        err = str(e)
        logger.exception("Falha Gmail connect")
        if "invalid_scope" in err:
            raise HTTPException(400, "Scope inválido. Regenere o refresh token.")
        if "invalid_grant" in err:
            raise HTTPException(400, "Refresh token expirado. Faça a autenticação OAuth novamente.")
        raise HTTPException(500, f"Gmail connect failed: {err}")


@router.post("/gmail/disconnect")
async def gmail_disconnect():
    global _monitor_task
    _state["gmail_connected"] = False
    _state["gmail_email"] = None
    _state["gmail_monitor_running"] = False
    if _monitor_task and not _monitor_task.done():
        _monitor_task.cancel()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────
# Scan Gmail — POST (original) + GET (correcção 405 para Flutter)
#
# CAUSA DO ERRO "405 Method Not Allowed":
#   CORRECÇÃO v8 (NON-BLOCKING):
#   Ambos POST e GET lançam o scan em BACKGROUND e devolvem imediatamente.
#   O Flutter usa polling em /gmail/emails/all (scanning: true/false)
#   para acompanhar o progresso — sem timeout no cliente.
# ─────────────────────────────────────────────────────────────────

# Task de scan em background (evita scans paralelos)
_bg_scan_task: Optional[asyncio.Task] = None


async def _bg_scan_background(max_results: int, auto_block: bool) -> None:
    """Executa scan em background — não bloqueia o HTTP request."""
    global _bg_scan_task
    try:
        logger.info("Background scan iniciado (%d emails)...", max_results)
        results = await scan_inbox(max_results=max_results, auto_block=auto_block)
        threats = sum(1 for r in results if r.get("analysis", {}).get("score", 0) >= 60)
        blocked_count = sum(1 for r in results if r.get("analysis", {}).get("blocked", False))
        _state["last_scan_at"] = datetime.now(timezone.utc).isoformat()
        _state["last_scan_threats"] = threats
        logger.info("Background scan concluído: %d emails, %d ameaças, %d bloqueados",
                    len(results), threats, blocked_count)
    except Exception as e:
        logger.exception("Background scan falhou: %s", e)
    finally:
        _bg_scan_task = None


@router.post("/gmail/scan", response_model=ScanResultV4)
async def gmail_scan_post(
    max_results: int = Query(default=20, ge=1, le=50),
    auto_block: bool = Query(default=True),
):
    """
    CORRIGIDO v8: Lança scan em BACKGROUND e devolve imediatamente.
    O Flutter usa polling em GET /gmail/emails/all para ver resultados.
    Elimina o TimeoutException que ocorria porque o scan bloqueava por > 120 s.
    """
    global _bg_scan_task
    if not _state.get("gmail_connected"):
        raise HTTPException(400, "Gmail não conectado")
    if _bg_scan_task and not _bg_scan_task.done():
        # Scan já em curso — devolver resposta vazia
        return ScanResultV4(scanned=0, threats_found=0, auto_blocked=0, results=[])
    _bg_scan_task = asyncio.create_task(_bg_scan_background(max_results, auto_block))
    return ScanResultV4(scanned=0, threats_found=0, auto_blocked=0, results=[])


@router.get("/gmail/scan", response_model=ScanResultV4)
async def gmail_scan_get(
    max_results: int = Query(default=20, ge=1, le=50),
    auto_block: bool = Query(default=True),
):
    """
    CORRIGIDO v8: Lança scan em BACKGROUND e devolve imediatamente.
    Mesmo comportamento que POST — sem bloquear o event loop.
    """
    global _bg_scan_task
    if not _state.get("gmail_connected"):
        raise HTTPException(400, "Gmail não conectado")
    if _bg_scan_task and not _bg_scan_task.done():
        return ScanResultV4(scanned=0, threats_found=0, auto_blocked=0, results=[])
    _bg_scan_task = asyncio.create_task(_bg_scan_background(max_results, auto_block))
    return ScanResultV4(scanned=0, threats_found=0, auto_blocked=0, results=[])


# ─────────────────────────────────────────────────────────────────
# Monitor contínuo — original
# ─────────────────────────────────────────────────────────────────

async def _gmail_monitor_loop(interval_seconds: int = 60):
    logger.info("🟢 Monitor Gmail iniciado (intervalo=%ss)", interval_seconds)
    _state["gmail_monitor_running"] = True
    try:
        while _state["gmail_monitor_running"]:
            try:
                messages = await asyncio.to_thread(_fetch_messages_sync, 20, True)
                new_msgs = [m for m in messages if m["id"] not in _state["seen_ids"]]
                if new_msgs:
                    logger.info("📬 %d novos emails detectados", len(new_msgs))
                    threats = 0
                    with Session(engine) as session:
                        for m in new_msgs:
                            try:
                                result = await orchestrate_email(
                                    m["sender"], m["headers"], m["body"])
                                a = Analysis(
                                    channel="email",
                                    score=result["score"],
                                    verdict=result["verdict"],
                                    details=result,
                                )
                                session.add(a); session.commit()
                                if result["score"] >= 60:
                                    threats += 1
                                    logger.warning(
                                        "⚠️ AMEAÇA: %s — score=%s",
                                        m["sender"], result["score"])
                                _state["seen_ids"].add(m["id"])
                            except Exception as e:
                                logger.warning("Erro msg %s: %s", m["id"], e)
                    _state["last_scan_at"] = datetime.now(timezone.utc).isoformat()
                    _state["last_scan_threats"] = threats
            except Exception as e:
                logger.exception("Erro no monitor: %s", e)
            await asyncio.sleep(interval_seconds)
    finally:
        _state["gmail_monitor_running"] = False
        logger.info("🔴 Monitor Gmail parado")


@router.post("/gmail/monitor/start")
async def gmail_monitor_start(interval_seconds: int = 60):
    global _monitor_task
    if not _state["gmail_connected"]:
        raise HTTPException(400, "Gmail não conectado")
    if _state["gmail_monitor_running"]:
        return {"ok": True, "already_running": True}
    _monitor_task = asyncio.create_task(_gmail_monitor_loop(interval_seconds))
    return {"ok": True, "interval": interval_seconds}


@router.post("/gmail/monitor/stop")
async def gmail_monitor_stop():
    global _monitor_task
    _state["gmail_monitor_running"] = False
    if _monitor_task and not _monitor_task.done():
        _monitor_task.cancel()
    return {"ok": True}


@router.post("/sms/toggle")
async def sms_toggle(enabled: bool):
    _state["sms_enabled"] = enabled
    return {"ok": True, "enabled": enabled}


# ═════════════════════════════════════════════════════════════════
# PATCH v4 — Endpoints adicionais (não substituem nada)
# ═════════════════════════════════════════════════════════════════

@router.get("/gmail/scan/v2", response_model=ScanResultV4)
async def gmail_scan_v2(
    max_results: int = Query(default=10, ge=1, le=50),
    auto_block: bool = Query(default=True),
):
    """[PATCH v4] Alias explícito para o pipeline async — mesmo que GET /gmail/scan."""
    return await _run_scan_v4(max_results=max_results, auto_block=auto_block)


@router.get("/gmail/blocked")
async def gmail_get_blocked(
    max_results: int = Query(default=50, ge=1, le=200),
):
    """[PATCH v4] Lista todos os emails bloqueados pelo PhishGuard."""
    try:
        blocked = await get_blocked_emails_async(max_results=max_results)
        return {"blocked": blocked, "total": len(blocked)}
    except Exception as e:
        logger.exception("gmail_get_blocked falhou")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gmail/block/{message_id}")
async def gmail_block_email(
    message_id: str,
    reasons: list[str] = None,
    score: int = 100,
):
    """[PATCH v4] Bloqueia manualmente um email (move para Lixo + label PHISHGUARD_BLOCKED)."""
    try:
        success = await block_email_async(
            message_id=message_id,
            reasons=reasons or ["manual_block"],
            score=score,
        )
        if not success:
            raise HTTPException(status_code=500, detail="Falha ao bloquear email")
        return {"success": True, "message_id": message_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("gmail_block falhou para %s", message_id)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gmail/unblock/{message_id}")
async def gmail_unblock_email(message_id: str):
    """[PATCH v4] Restaura um email bloqueado para a caixa de entrada."""
    try:
        ok = await unblock_email_async(message_id)
        if not ok:
            raise HTTPException(status_code=500, detail="Não foi possível restaurar o email")
        return {"success": True, "message_id": message_id, "restored": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("gmail_unblock falhou para %s", message_id)
        raise HTTPException(status_code=500, detail=str(e))
    