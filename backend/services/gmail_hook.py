"""
backend/services/gmail_hook.py
────────────────────────────────
Gmail API — CORRECÇÕES v22

CORRECÇÕES v22:
- Timeout da análise individual aumentado para 120 segundos
  (permite que APIs externas completem sem interrupção).
- Restante código mantido da versão v21 (watcher leve, OAuth, etc.).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


# ─── Configuração OAuth2 ──────────────────────────────────────────

def _get_settings():
    try:
        from backend.core.config import settings
        return settings
    except Exception:
        return None


def _setting(name: str, default: str = "") -> str:
    s = _get_settings()
    return getattr(s, name, None) or os.getenv(name, default)


GMAIL_CLIENT_ID     = _setting("GMAIL_CLIENT_ID")
GMAIL_CLIENT_SECRET = _setting("GMAIL_CLIENT_SECRET")
GMAIL_REDIRECT_URI  = os.getenv("GMAIL_REDIRECT_URI", "http://localhost:8000/integrations/auth/gmail/callback")
GMAIL_TOKEN_URL     = "https://oauth2.googleapis.com/token"
GMAIL_AUTH_URL      = "https://accounts.google.com/o/oauth2/v2/auth"
GMAIL_API_BASE      = "https://gmail.googleapis.com/gmail/v1/users/me"

GMAIL_SCOPES = " ".join([
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
])

REQUEST_TIMEOUT    = int(os.getenv("GMAIL_REQUEST_TIMEOUT", "15"))
BLOCKED_LABEL_NAME = "PHISHGUARD_BLOCKED"
ANALYSE_TIMEOUT    = int(os.getenv("GMAIL_ANALYSE_TIMEOUT", "120"))   # ← 120 segundos

# ─── Configuração do watcher ──────────────────────────────────────
WATCHER_INTERVAL_SECS = int(os.getenv("WATCHER_INTERVAL_SECS", "10"))
SCAN_MAX_RESULTS      = int(os.getenv("SCAN_MAX_RESULTS", "10"))

# ─── Estado global ────────────────────────────────────────────────
_token_cache: Dict[str, object] = {}
_TOKEN_TTL = 3500

_analysed_cache: List[Dict] = []
_last_scan_ts: float = 0.0

_analysed_ids: set[str]        = set()
_scan_running: bool             = False
_watcher_task: Optional[asyncio.Task] = None
_watcher_error_count: int       = 0

_TOKENS_FILE = os.path.join(os.path.dirname(__file__), ".gmail_tokens.json")

_gmail_diag: dict = {
    "connected":                False,
    "refresh_token_configured": False,
    "access_token_valid":       False,
    "last_error":               None,
    "last_check":               None,
    "watcher_running":          False,
    "last_watcher_scan":        None,
    "emails_blocked_total":     0,
}

_notification_manager = None


def set_notification_manager(manager):
    global _notification_manager
    _notification_manager = manager


# ─── Token persistence ────────────────────────────────────────────

def _load_refresh_token() -> Optional[str]:
    s = _get_settings()
    token = getattr(s, "GMAIL_REFRESH_TOKEN", None) or os.getenv("GMAIL_REFRESH_TOKEN")
    if token:
        _gmail_diag["refresh_token_configured"] = True
        return token

    try:
        if os.path.exists(_TOKENS_FILE):
            with open(_TOKENS_FILE) as f:
                data  = json.load(f)
                token = data.get("refresh_token")
                if token:
                    _gmail_diag["refresh_token_configured"] = True
                    return token
    except Exception as e:
        logger.warning("Erro ao carregar tokens locais: %s", e)

    _gmail_diag["refresh_token_configured"] = False
    return None


def _save_refresh_token(refresh_token: str) -> None:
    try:
        with open(_TOKENS_FILE, "w") as f:
            json.dump({"refresh_token": refresh_token, "saved_at": time.time()}, f)
        logger.info("✅ Gmail refresh_token guardado em %s", _TOKENS_FILE)
        _gmail_diag["refresh_token_configured"] = True
    except Exception as e:
        logger.warning("Não foi possível guardar refresh_token: %s", e)


# ─── Diagnóstico ──────────────────────────────────────────────────

def get_gmail_diagnostics() -> dict:
    s = _get_settings()
    return {
        **_gmail_diag,
        "refresh_token_configured":  bool(
            getattr(s, "GMAIL_REFRESH_TOKEN", None) or os.getenv("GMAIL_REFRESH_TOKEN")
        ),
        "refresh_token_from_file":   os.path.exists(_TOKENS_FILE),
        "client_id_configured":      bool(GMAIL_CLIENT_ID),
        "client_secret_configured":  bool(GMAIL_CLIENT_SECRET),
        "redirect_uri":              GMAIL_REDIRECT_URI,
        "watcher_interval_secs":     WATCHER_INTERVAL_SECS,
        "watcher_active":            (
            _watcher_task is not None and not _watcher_task.done()
        ),
    }


# ─── OAuth2 Flow ──────────────────────────────────────────────────

def get_gmail_auth_url(state: str = "phishguard") -> str:
    if not GMAIL_CLIENT_ID:
        raise ValueError("GMAIL_CLIENT_ID não configurado.")
    if not GMAIL_CLIENT_SECRET:
        raise ValueError("GMAIL_CLIENT_SECRET não configurado.")

    from urllib.parse import urlencode
    params = {
        "client_id":     GMAIL_CLIENT_ID,
        "redirect_uri":  GMAIL_REDIRECT_URI,
        "response_type": "code",
        "scope":         GMAIL_SCOPES,
        "access_type":   "offline",
        "prompt":        "consent",
        "state":         state,
    }
    return f"{GMAIL_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str) -> Dict:
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.post(GMAIL_TOKEN_URL, data={
            "client_id":     GMAIL_CLIENT_ID,
            "client_secret": GMAIL_CLIENT_SECRET,
            "code":          code,
            "redirect_uri":  GMAIL_REDIRECT_URI,
            "grant_type":    "authorization_code",
        })
        r.raise_for_status()
        data = r.json()

    access_token  = data.get("access_token", "")
    refresh_token = data.get("refresh_token", "")

    if refresh_token:
        _save_refresh_token(refresh_token)
        _token_cache["access_token"] = access_token
        _token_cache["expires_at"]   = time.time() + data.get("expires_in", 3600)
        _gmail_diag["connected"]          = True
        _gmail_diag["access_token_valid"] = True
        logger.info("✅ Gmail: tokens obtidos com sucesso")
        _ensure_watcher_running()

    return {"access_token": access_token, "refresh_token": refresh_token}


def is_gmail_connected() -> bool:
    refresh_token = _load_refresh_token()
    if not refresh_token:
        _gmail_diag["connected"]  = False
        _gmail_diag["last_error"] = "GMAIL_REFRESH_TOKEN não configurado"
        return False
    _gmail_diag["connected"]  = True
    _gmail_diag["last_check"] = time.time()
    return True


def is_scan_running() -> bool:
    return _scan_running


# ─── Access Token ─────────────────────────────────────────────────

async def _get_access_token_async() -> Optional[str]:
    expires_at = float(_token_cache.get("expires_at", 0))
    if time.time() < expires_at - 60:
        _gmail_diag["access_token_valid"] = True
        return str(_token_cache["access_token"])

    refresh_token = _load_refresh_token()
    if not refresh_token:
        _gmail_diag["connected"]          = False
        _gmail_diag["access_token_valid"] = False
        _gmail_diag["last_error"]         = "GMAIL_REFRESH_TOKEN não configurado"
        logger.error("❌ Gmail: refresh_token não disponível.")
        return None

    client_id     = GMAIL_CLIENT_ID or _setting("GMAIL_CLIENT_ID")
    client_secret = GMAIL_CLIENT_SECRET or _setting("GMAIL_CLIENT_SECRET")

    if not client_id or not client_secret:
        _gmail_diag["last_error"] = "GMAIL_CLIENT_ID ou GMAIL_CLIENT_SECRET não configurados"
        return None

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.post(GMAIL_TOKEN_URL, data={
                "client_id":     client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type":    "refresh_token",
            })

            if r.status_code != 200:
                error_data: dict = {}
                try:
                    error_data = r.json()
                except Exception:
                    pass
                error_desc = error_data.get("error_description", r.text[:200])
                error_code = error_data.get("error", "unknown")
                _gmail_diag["access_token_valid"] = False
                _gmail_diag["last_error"]         = f"{error_code}: {error_desc}"

                if error_code == "invalid_grant":
                    logger.error(
                        "🔴 GMAIL_REFRESH_TOKEN INVÁLIDO! "
                        "Acede a /integrations/auth/gmail/url para re‑autorizar."
                    )
                return None

            data  = r.json()
            token = data.get("access_token")
            if token:
                _token_cache["access_token"] = token
                _token_cache["expires_at"]   = time.time() + data.get("expires_in", 3600)
                _gmail_diag["access_token_valid"] = True
                _gmail_diag["connected"]          = True
                _gmail_diag["last_error"]         = None
                _gmail_diag["last_check"]         = time.time()
            return token

    except Exception as exc:
        _gmail_diag["last_error"] = str(exc)[:200]
        logger.error("Erro ao obter access token Gmail: %s", exc)
        return None


def _auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ─── Gmail API helpers ────────────────────────────────────────────

async def _list_message_ids(
    token: str,
    max_results: int = 30,
    query: str = "",
) -> List[str]:
    q = query or "in:inbox is:unread newer_than:1d"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.get(
                f"{GMAIL_API_BASE}/messages",
                headers=_auth_headers(token),
                params={
                    "maxResults":       max_results,
                    "q":                q,
                    "includeSpamTrash": False,
                },
            )
            r.raise_for_status()
            messages = r.json().get("messages", [])
            return [m["id"] for m in messages]
    except Exception as exc:
        logger.error("❌ _list_message_ids falhou: %s", exc)
        return []


async def _has_new_emails() -> bool:
    token = await _get_access_token_async()
    if not token:
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"{GMAIL_API_BASE}/messages",
                headers=_auth_headers(token),
                params={
                    "maxResults":       5,
                    "q":                "in:inbox is:unread newer_than:1d",
                    "includeSpamTrash": False,
                },
            )
            r.raise_for_status()
            messages = r.json().get("messages", [])
            for m in messages:
                if m["id"] not in _analysed_ids:
                    return True
            return False
    except Exception as e:
        logger.debug("_has_new_emails erro: %s", e)
        return False


async def _get_message_async(token: str, msg_id: str) -> Optional[Dict]:
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.get(
                f"{GMAIL_API_BASE}/messages/{msg_id}",
                headers=_auth_headers(token),
                params={"format": "full"},
            )
            r.raise_for_status()
            msg = r.json()

        payload = msg.get("payload", {})
        headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}

        subject       = headers.get("subject", "(sem assunto)")
        sender        = headers.get("from", "")
        date          = headers.get("date", "")
        internal_date = int(msg.get("internalDate", 0))

        body_text = ""
        body_html = ""

        def _extract_parts(parts):
            nonlocal body_text, body_html
            for part in parts:
                mt   = part.get("mimeType", "")
                data = part.get("body", {}).get("data", "")
                if data:
                    try:
                        decoded = base64.urlsafe_b64decode(data + "==").decode(
                            "utf-8", errors="replace"
                        )
                        if mt == "text/plain":
                            body_text += decoded
                        elif mt == "text/html":
                            body_html += decoded
                    except Exception:
                        pass
                sub_parts = part.get("parts", [])
                if sub_parts:
                    _extract_parts(sub_parts)

        top_parts = payload.get("parts", [])
        if top_parts:
            _extract_parts(top_parts)
        else:
            raw_body = payload.get("body", {}).get("data", "")
            if raw_body:
                try:
                    decoded = base64.urlsafe_b64decode(raw_body + "==").decode(
                        "utf-8", errors="replace"
                    )
                    if payload.get("mimeType", "") == "text/html":
                        body_html = decoded
                    else:
                        body_text = decoded
                except Exception:
                    pass

        return {
            "id":            msg_id,
            "subject":       subject,
            "sender":        sender,
            "date":          date,
            "internal_date": internal_date,
            "snippet":       msg.get("snippet", ""),
            "body_text":     body_text[:5000],
            "body_html":     body_html[:10000],
            "label_ids":     msg.get("labelIds", []),
            "headers_raw":   dict(headers),
        }
    except Exception as exc:
        logger.error("_get_message_async falhou para %s: %s", msg_id, exc)
        return None


# ─── Label management ─────────────────────────────────────────────

_blocked_label_id_cache: Optional[str] = None


async def _get_or_create_blocked_label(token: str) -> Optional[str]:
    global _blocked_label_id_cache
    if _blocked_label_id_cache:
        return _blocked_label_id_cache

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.get(f"{GMAIL_API_BASE}/labels", headers=_auth_headers(token))
            r.raise_for_status()
            labels = r.json().get("labels", [])

        for label in labels:
            if label.get("name") == BLOCKED_LABEL_NAME:
                _blocked_label_id_cache = label["id"]
                return label["id"]

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.post(
                f"{GMAIL_API_BASE}/labels",
                headers={**_auth_headers(token), "Content-Type": "application/json"},
                json={
                    "name":                  BLOCKED_LABEL_NAME,
                    "labelListVisibility":   "labelShow",
                    "messageListVisibility": "show",
                    "color": {
                        "backgroundColor": "#cc0000",
                        "textColor":       "#ffffff",
                    },
                },
            )
            r.raise_for_status()
            label_id = r.json().get("id")
            _blocked_label_id_cache = label_id
            return label_id

    except Exception as exc:
        logger.error("Erro ao gerir label PHISHGUARD_BLOCKED: %s", exc)
        return None


async def block_email_async(
    message_id: str,
    reasons: List[str] | None = None,
    score: int = 100,
) -> bool:
    token = await _get_access_token_async()
    if not token:
        return False

    try:
        blocked_label_id = await _get_or_create_blocked_label(token)

        add_labels    = ["TRASH"]
        remove_labels = ["INBOX", "UNREAD"]

        if blocked_label_id:
            add_labels.append(blocked_label_id)

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.post(
                f"{GMAIL_API_BASE}/messages/{message_id}/modify",
                headers={**_auth_headers(token), "Content-Type": "application/json"},
                json={
                    "addLabelIds":    add_labels,
                    "removeLabelIds": remove_labels,
                },
            )
            if r.status_code not in (200, 204):
                logger.error(
                    "block_email_async: API retornou %d para %s — %s",
                    r.status_code, message_id, r.text[:200],
                )
                return False

        _gmail_diag["emails_blocked_total"] = (
            _gmail_diag.get("emails_blocked_total", 0) + 1
        )
        logger.info(
            "✅ Gmail: email %s bloqueado → TRASH + label %s (score=%d)",
            message_id, BLOCKED_LABEL_NAME, score,
        )
        return True
    except Exception as exc:
        logger.error("Erro ao bloquear email %s: %s", message_id, exc)
        return False


async def unblock_email_async(message_id: str) -> bool:
    token = await _get_access_token_async()
    if not token:
        return False

    try:
        blocked_label_id = await _get_or_create_blocked_label(token)
        remove_labels = ["TRASH", "SPAM"]
        if blocked_label_id:
            remove_labels.append(blocked_label_id)

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.post(
                f"{GMAIL_API_BASE}/messages/{message_id}/modify",
                headers={**_auth_headers(token), "Content-Type": "application/json"},
                json={
                    "addLabelIds":    ["INBOX"],
                    "removeLabelIds": remove_labels,
                },
            )
            r.raise_for_status()
            logger.info("Gmail: email %s restaurado para INBOX", message_id)
            return True
    except Exception as exc:
        logger.error("Erro ao restaurar email %s: %s", message_id, exc)
        return False


# ─── Notificações ─────────────────────────────────────────────────

async def _send_phishing_notification(
    email_data: Dict, score: int, verdict: str, reasons: List[str]
):
    global _notification_manager
    if _notification_manager is None:
        return
    try:
        email_info = email_data.get("email", email_data)
        notification = {
            "type":  "phishing_detected",
            "title": "🚨 Phishing Bloqueado!" if score >= 70 else "⚠️ Email Suspeito",
            "body":  f"De: {email_info.get('sender', '?')[:50]} — Score: {score}/100",
            "data": {
                "email_id": email_info.get("id", ""),
                "score":    score,
                "verdict":  verdict,
                "reasons":  reasons[:3],
                "sender":   email_info.get("sender", ""),
                "subject":  email_info.get("subject", ""),
            },
            "action_required": score >= 70,
        }
        await _notification_manager.send_notification(notification)
    except Exception as e:
        logger.warning("Falha ao enviar notificação: %s", e)


# ─── Análise de email individual ──────────────────────────────────

async def _analyse_single_email(
    email_data: Dict,
    auto_block: bool = True,
) -> Optional[Dict]:
    msg_id  = email_data.get("id", "")
    subject = email_data.get("subject", "")
    sender  = email_data.get("sender", "")

    try:
        headers_str = json.dumps(email_data.get("headers_raw", {}))
        body        = email_data.get("body_text") or email_data.get("body_html", "")

        score   = 0
        verdict = "SEGURO"
        reasons: List[str] = []
        ml_data: dict = {}

        # Tentar hybrid_analyzer primeiro
        try:
            from backend.services.hybrid_analyzer import hybrid_analyze_email

            result = await asyncio.wait_for(
                hybrid_analyze_email(
                    sender=sender,
                    headers=headers_str,
                    body=body,
                    run_external_apis=True,
                    timeout_total=55.0,
                ),
                timeout=float(ANALYSE_TIMEOUT),   # ← 120 segundos
            )
            score   = result.score
            verdict = result.verdict
            reasons = result.reasons
            ml_data = result.ml or {}

        except (ImportError, AttributeError):
            logger.debug("hybrid_analyzer não disponível — usando email_analyzer")
            from backend.services.email_analyzer import analyze_email_async

            analysis = await asyncio.wait_for(
                analyze_email_async(headers_str, body),
                timeout=float(ANALYSE_TIMEOUT),
            )
            score   = analysis["score"]
            verdict = analysis["classification"]
            reasons = analysis["reasons"]
            ml_data = {}

        blocked = False
        if auto_block and score >= 70:
            logger.info("🛡️ Auto‑bloqueando email %s (score=%d)", msg_id, score)
            blocked = await block_email_async(msg_id, reasons, score)
            if blocked:
                reasons = [f"BLOQUEADO: score={score} — movido para o lixo"] + list(reasons)

        if score >= 60:
            await _send_phishing_notification(email_data, score, verdict, reasons[:5])

        return {
            "email": {
                "id":            msg_id,
                "subject":       subject,
                "sender":        sender,
                "date":          email_data.get("date", ""),
                "snippet":       email_data.get("snippet", ""),
                "internal_date": email_data.get("internal_date", 0),
            },
            "analysis": {
                "score":   score,
                "verdict": verdict,
                "reasons": reasons,
                "blocked": blocked,
                "ml":      ml_data,
            },
        }

    except asyncio.TimeoutError:
        logger.warning("Timeout na análise do email %s", msg_id)
        return _make_timeout_result(msg_id, subject, sender, email_data)
    except Exception as exc:
        logger.error("_analyse_single_email falhou para %s: %s", msg_id, exc)
        return _make_error_result(msg_id, subject, sender, email_data, exc)


def _make_timeout_result(msg_id, subject, sender, email_data):
    return {
        "email": {
            "id": msg_id, "subject": subject, "sender": sender,
            "date": email_data.get("date", ""),
            "snippet": email_data.get("snippet", ""),
            "internal_date": email_data.get("internal_date", 0),
        },
        "analysis": {
            "score":   30,
            "verdict": "SUSPEITO",
            "reasons": ["analysis_timeout — verificar manualmente"],
            "blocked": False,
            "ml":      {},
        },
    }


def _make_error_result(msg_id, subject, sender, email_data, exc):
    return {
        "email": {
            "id": msg_id, "subject": subject, "sender": sender,
            "date": email_data.get("date", ""),
            "snippet": email_data.get("snippet", ""),
            "internal_date": email_data.get("internal_date", 0),
        },
        "analysis": {
            "score":   30,
            "verdict": "SUSPEITO",
            "reasons": [f"Erro na análise: {type(exc).__name__}"],
            "blocked": False,
            "error":   str(exc),
            "ml":      {},
        },
    }


def _add_to_analysed_cache(result: Dict) -> None:
    global _analysed_cache
    email_id = result.get("email", {}).get("id", "")

    _analysed_cache = [
        e for e in _analysed_cache
        if e.get("email", {}).get("id") != email_id
    ]
    _analysed_cache.append(result)
    _analysed_cache.sort(
        key=lambda e: e.get("email", {}).get("internal_date", 0),
        reverse=True,
    )
    if len(_analysed_cache) > 200:
        _analysed_cache = _analysed_cache[:200]

    _analysed_ids.add(email_id)


# ─── Scan incremental ─────────────────────────────────────────────

async def scan_inbox(
    max_results: int = 30,
    query: str = "",
    auto_block: bool = True,
    incremental: bool = False,
) -> List[Dict]:
    global _last_scan_ts, _scan_running
    _scan_running = True

    try:
        token = await _get_access_token_async()
        if not token:
            return []

        message_ids = await _list_message_ids(token, max_results, query)
        if not message_ids:
            return []

        if incremental:
            new_ids = [mid for mid in message_ids if mid not in _analysed_ids]
            if not new_ids:
                logger.info("Scan incremental: nenhum email novo.")
                _last_scan_ts = time.monotonic()
                return []
            message_ids = new_ids
            logger.info("Gmail: %d emails novos para análise.", len(message_ids))
        else:
            logger.info("Gmail: %d emails para análise.", len(message_ids))

        fetch_sem = asyncio.Semaphore(10)

        async def _fetch_with_sem(mid: str) -> Optional[Dict]:
            async with fetch_sem:
                return await _get_message_async(token, mid)

        email_data_list = await asyncio.gather(
            *[_fetch_with_sem(mid) for mid in message_ids],
            return_exceptions=True,
        )

        analyse_sem = asyncio.Semaphore(3)

        async def _analyse_with_sem(ed: Dict) -> Optional[Dict]:
            async with analyse_sem:
                result = await _analyse_single_email(ed, auto_block=auto_block)
                if result:
                    _add_to_analysed_cache(result)
                return result

        results = await asyncio.gather(
            *[
                _analyse_with_sem(ed)
                for ed in email_data_list
                if isinstance(ed, dict) and ed
            ],
            return_exceptions=True,
        )

        final: List[Dict] = []
        threats       = 0
        blocked_count = 0
        for r in results:
            if isinstance(r, Exception):
                logger.warning("Erro num email: %s", r)
                continue
            if r is not None:
                final.append(r)
                s = r.get("analysis", {}).get("score", 0)
                if s >= 60:
                    threats += 1
                if r.get("analysis", {}).get("blocked"):
                    blocked_count += 1

        _last_scan_ts = time.monotonic()
        logger.info(
            "✅ Scan concluído: %d emails, %d ameaças, %d bloqueados",
            len(final), threats, blocked_count,
        )
        return final
    finally:
        _scan_running = False


# ═══════════════════════════════════════════════════════════════════
# WATCHER com backoff exponencial
# ═══════════════════════════════════════════════════════════════════

async def _simple_watcher():
    global _watcher_error_count

    logger.info(
        "🔄 Watcher simples iniciado (intervalo=%ds, max_emails=%d)",
        WATCHER_INTERVAL_SECS, SCAN_MAX_RESULTS,
    )
    _gmail_diag["watcher_running"] = True

    await asyncio.sleep(3)

    while True:
        try:
            if is_gmail_connected() and not _scan_running:
                if await _has_new_emails():
                    logger.info("📬 Novos emails detetados! Iniciando scan incremental.")
                    _gmail_diag["last_watcher_scan"] = time.time()
                    await scan_inbox(
                        max_results=SCAN_MAX_RESULTS,
                        auto_block=True,
                        incremental=True,
                    )
                else:
                    logger.debug("Watcher: sem emails novos.")
            _watcher_error_count = 0
        except Exception as exc:
            _watcher_error_count += 1
            backoff = min(300, WATCHER_INTERVAL_SECS * (2 ** min(_watcher_error_count, 5)))
            logger.error(
                "Erro no watcher (tentativa %d, próximo em %ds): %s",
                _watcher_error_count, backoff, exc,
            )
            await asyncio.sleep(backoff)
            continue

        await asyncio.sleep(WATCHER_INTERVAL_SECS)


def _ensure_watcher_running():
    global _watcher_task
    if _watcher_task is not None and not _watcher_task.done():
        return
    try:
        loop = asyncio.get_running_loop()
        _watcher_task = loop.create_task(_simple_watcher())
        logger.info("✅ Watcher simples agendado.")
    except RuntimeError:
        logger.warning("Não foi possível iniciar o watcher (loop não disponível).")


def start_auto_scan_watcher():
    _ensure_watcher_running()


# ─── API PÚBLICA ──────────────────────────────────────────────────

async def get_all_analysed_emails(max_results: int = 100) -> List[Dict]:
    return _analysed_cache[:max_results]


async def force_refresh(max_results: int = 30) -> List[Dict]:
    global _scan_running, _analysed_ids
    if not _scan_running:
        _scan_running = True
        _analysed_ids.clear()
        logger.info("force_refresh: IDs limpos, scan completo iniciado")
        asyncio.get_running_loop().create_task(
            scan_inbox(max_results=max_results, auto_block=True, incremental=False)
        )
    await asyncio.sleep(1)
    return _analysed_cache[:max_results]


async def get_blocked_emails_async(max_results: int = 50) -> List[Dict]:
    token = await _get_access_token_async()
    if not token:
        return []

    try:
        blocked_label_id = await _get_or_create_blocked_label(token)
        if not blocked_label_id:
            return []

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.get(
                f"{GMAIL_API_BASE}/messages",
                headers=_auth_headers(token),
                params={"maxResults": max_results, "labelIds": blocked_label_id},
            )
            r.raise_for_status()
            message_ids = [m["id"] for m in r.json().get("messages", [])]

        tasks   = [_get_message_async(token, mid) for mid in message_ids[:max_results]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        blocked = []
        for data in results:
            if isinstance(data, dict) and data:
                cached = next(
                    (
                        e for e in _analysed_cache
                        if e.get("email", {}).get("id") == data["id"]
                    ),
                    None,
                )
                if cached:
                    cached_copy = dict(cached)
                    cached_copy["analysis"] = {
                        **cached_copy.get("analysis", {}),
                        "blocked": True,
                    }
                    blocked.append(cached_copy)
                else:
                    blocked.append({
                        "email": {
                            "id":            data["id"],
                            "subject":       data["subject"],
                            "sender":        data["sender"],
                            "date":          data["date"],
                            "snippet":       data["snippet"],
                            "internal_date": data.get("internal_date", 0),
                        },
                        "analysis": {
                            "score":   80,
                            "verdict": "NÃO SEGURO",
                            "reasons": ["BLOQUEADO pelo PhishGuard — movido para o lixo"],
                            "blocked": True,
                        },
                    })
        return blocked

    except Exception as exc:
        logger.error("Erro ao listar emails bloqueados: %s", exc)
        return []
    