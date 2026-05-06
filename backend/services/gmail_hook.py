"""
backend/services/gmail_hook.py
───────────────────────────────
Gmail API — CORRECÇÕES v16

CORRECÇÕES v16:
- GMAIL_REDIRECT_URI usa localhost:8000 (obrigatório para Google OAuth)
- _get_access_token_async() com melhor logging de erros
- scan_inbox() define _scan_running=False SEMPRE (finally)
- is_gmail_connected() verifica refresh_token existe
- get_all_analysed_emails() inicia scan se cache vazia
- Diagnóstico detalhado via get_gmail_diagnostics()
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

from backend.core.config import settings

logger = logging.getLogger(__name__)

# ─── Configuração OAuth2 ──────────────────────────────────────────

GMAIL_CLIENT_ID     = settings.GMAIL_CLIENT_ID
GMAIL_CLIENT_SECRET = settings.GMAIL_CLIENT_SECRET

# ⚠️ CRÍTICO: Google OAuth NÃO permite IPs privados (172.x, 192.x, 10.x)
# como redirect_uri. Apenas localhost ou domínios públicos com HTTPS.
GMAIL_REDIRECT_URI = "http://localhost:8000/auth/gmail/callback"

GMAIL_TOKEN_URL  = "https://oauth2.googleapis.com/token"
GMAIL_AUTH_URL   = "https://accounts.google.com/o/oauth2/v2/auth"
GMAIL_API_BASE   = "https://gmail.googleapis.com/gmail/v1/users/me"

GMAIL_SCOPES = " ".join([
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
])

REQUEST_TIMEOUT    = 15
BLOCKED_LABEL_NAME = "PHISHGUARD_BLOCKED"

# ─── Estado global ────────────────────────────────────────────────

_token_cache: Dict[str, float | str] = {}
_TOKEN_TTL = 3500

_analysed_cache: List[Dict] = []
_last_scan_ts: float = 0.0
_CACHE_TTL_SECS = 120

_analysed_ids: set[str] = set()
_scan_running: bool = False

_TOKENS_FILE = os.path.join(os.path.dirname(__file__), ".gmail_tokens.json")

_gmail_diag: dict = {
    "connected": False,
    "refresh_token_configured": False,
    "access_token_valid": False,
    "last_error": None,
    "last_check": None,
}


# ─── Token persistence ────────────────────────────────────────────

def _load_refresh_token() -> Optional[str]:
    """Carrega o refresh_token do Gmail."""
    # Primeiro: usar o token do .env
    if settings.GMAIL_REFRESH_TOKEN:
        _gmail_diag["refresh_token_configured"] = True
        logger.debug("Gmail: refresh_token encontrado no .env")
        return settings.GMAIL_REFRESH_TOKEN
    
    # Segundo: tentar ficheiro de tokens guardado localmente
    try:
        if os.path.exists(_TOKENS_FILE):
            with open(_TOKENS_FILE) as f:
                data = json.load(f)
                token = data.get("refresh_token")
                if token:
                    _gmail_diag["refresh_token_configured"] = True
                    logger.debug("Gmail: refresh_token encontrado no ficheiro local")
                    return token
    except Exception as e:
        logger.warning("Erro ao carregar tokens locais: %s", e)
    
    _gmail_diag["refresh_token_configured"] = False
    return None


def _save_refresh_token(refresh_token: str) -> None:
    """Guarda o refresh_token localmente."""
    try:
        with open(_TOKENS_FILE, "w") as f:
            json.dump({"refresh_token": refresh_token, "saved_at": time.time()}, f)
        logger.info("✅ Gmail refresh_token guardado em %s", _TOKENS_FILE)
        _gmail_diag["refresh_token_configured"] = True
    except Exception as e:
        logger.warning("Não foi possível guardar refresh_token: %s", e)


# ─── Diagnóstico ──────────────────────────────────────────────────

def get_gmail_diagnostics() -> dict:
    """Devolve diagnóstico detalhado do estado do Gmail."""
    return {
        **_gmail_diag,
        "last_check": _gmail_diag.get("last_check"),
        "refresh_token_configured": bool(settings.GMAIL_REFRESH_TOKEN),
        "refresh_token_from_file": os.path.exists(_TOKENS_FILE),
        "client_id_configured": bool(settings.GMAIL_CLIENT_ID),
        "client_secret_configured": bool(GMAIL_CLIENT_SECRET),
        "redirect_uri": GMAIL_REDIRECT_URI,
    }


# ─── OAuth2 Flow ──────────────────────────────────────────────────

def get_gmail_auth_url(state: str = "phishguard") -> str:
    """Gera URL de autorização OAuth2 do Google."""
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
    auth_url = f"{GMAIL_AUTH_URL}?{urlencode(params)}"
    logger.info("Gmail auth URL gerado com redirect_uri: %s", GMAIL_REDIRECT_URI)
    return auth_url


async def exchange_code_for_tokens(code: str) -> Dict:
    """
    Troca o código de autorização por access_token e refresh_token.
    O refresh_token é guardado automaticamente.
    """
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
        _gmail_diag["connected"] = True
        _gmail_diag["access_token_valid"] = True
        logger.info("✅ Gmail: tokens obtidos com sucesso")

    return {"access_token": access_token, "refresh_token": refresh_token}


def is_gmail_connected() -> bool:
    """
    Verifica se o Gmail está conectado.
    Retorna True se o refresh_token existe (no .env ou ficheiro local).
    """
    refresh_token = _load_refresh_token()
    
    if not refresh_token:
        _gmail_diag["connected"] = False
        _gmail_diag["last_error"] = "GMAIL_REFRESH_TOKEN não configurado"
        logger.warning("⚠️ Gmail: NÃO conectado — refresh_token em falta")
        return False
    
    _gmail_diag["connected"] = True
    _gmail_diag["last_check"] = time.time()
    logger.info("✅ Gmail: refresh_token configurado")
    return True


def is_scan_running() -> bool:
    """Retorna True se há um scan em curso."""
    return _scan_running


# ─── Access Token ─────────────────────────────────────────────────

async def _get_access_token_async() -> Optional[str]:
    """
    Obtém um access token válido para a Gmail API.
    Tenta renovar com o refresh_token se necessário.
    """
    # Verificar cache
    expires_at = _token_cache.get("expires_at", 0)
    if time.time() < float(expires_at) - 60:
        _gmail_diag["access_token_valid"] = True
        _gmail_diag["last_check"] = time.time()
        return str(_token_cache["access_token"])

    refresh_token = _load_refresh_token()
    if not refresh_token:
        _gmail_diag["connected"] = False
        _gmail_diag["access_token_valid"] = False
        _gmail_diag["last_error"] = "GMAIL_REFRESH_TOKEN não configurado"
        _gmail_diag["last_check"] = time.time()
        logger.error("❌ Gmail: refresh_token não disponível.")
        return None
    
    if not GMAIL_CLIENT_ID or not GMAIL_CLIENT_SECRET:
        _gmail_diag["last_error"] = "GMAIL_CLIENT_ID ou GMAIL_CLIENT_SECRET não configurados"
        _gmail_diag["last_check"] = time.time()
        logger.error("❌ Gmail: Client ID ou Client Secret em falta.")
        return None

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.post(GMAIL_TOKEN_URL, data={
                "client_id":     GMAIL_CLIENT_ID,
                "client_secret": GMAIL_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type":    "refresh_token",
            })

            if r.status_code != 200:
                error_data = {}
                try:
                    error_data = r.json()
                except Exception:
                    pass
                error_desc = error_data.get("error_description", r.text[:200])
                error_code = error_data.get("error", "unknown")
                
                _gmail_diag["access_token_valid"] = False
                _gmail_diag["last_error"] = f"{error_code}: {error_desc}"
                _gmail_diag["last_check"] = time.time()
                
                logger.error(
                    "❌ Gmail token refresh falhou: %d %s — %s",
                    r.status_code, error_code, error_desc,
                )
                
                if error_code == "invalid_grant":
                    logger.error(
                        "🔴 GMAIL_REFRESH_TOKEN INVÁLIDO OU EXPIRADO!\n"
                        "   Para corrigir:\n"
                        "   1. Acede a: http://localhost:8000/integrations/auth/gmail/url\n"
                        "   2. Autoriza a aplicação\n"
                        "   3. O novo token será guardado automaticamente"
                    )
                
                return None

            data = r.json()

        token = data.get("access_token")
        if token:
            _token_cache["access_token"] = token
            _token_cache["expires_at"]   = time.time() + data.get("expires_in", 3600)
            _gmail_diag["access_token_valid"] = True
            _gmail_diag["connected"] = True
            _gmail_diag["last_error"] = None
            _gmail_diag["last_check"] = time.time()
            logger.info("✅ Gmail: access token renovado com sucesso")
        else:
            _gmail_diag["access_token_valid"] = False
            _gmail_diag["last_error"] = "Resposta sem access_token"
            
        return token

    except httpx.TimeoutException:
        _gmail_diag["last_error"] = "Timeout ao contactar Google"
        _gmail_diag["last_check"] = time.time()
        logger.error("Timeout ao renovar access token Gmail")
        return None
    except Exception as exc:
        _gmail_diag["last_error"] = str(exc)[:200]
        _gmail_diag["last_check"] = time.time()
        logger.error("Erro ao obter access token Gmail: %s", exc)
        return None


def _auth_headers(token: str) -> Dict[str, str]:
    """Headers de autorização para a Gmail API."""
    return {"Authorization": f"Bearer {token}"}


# ─── Gmail API helpers ────────────────────────────────────────────

async def _list_message_ids(
    token: str,
    max_results: int = 30,
    query: str = "",
) -> List[str]:
    """Lista IDs das mensagens na inbox."""
    q = query or "newer_than:7d"
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
            logger.info("✅ Gmail: %d emails encontrados na inbox", len(messages))
            return [m["id"] for m in messages]
    except Exception as exc:
        logger.error("❌ _list_message_ids falhou: %s", exc)
        return []


async def _get_message_async(token: str, msg_id: str) -> Optional[Dict]:
    """Obtém detalhes de uma mensagem específica."""
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.get(
                f"{GMAIL_API_BASE}/messages/{msg_id}",
                headers=_auth_headers(token),
                params={"format": "full"},
            )
            r.raise_for_status()
            msg = r.json()

        payload  = msg.get("payload", {})
        headers  = {h["name"].lower(): h["value"]
                    for h in payload.get("headers", [])}

        subject       = headers.get("subject", "(sem assunto)")
        sender        = headers.get("from", "")
        date          = headers.get("date", "")
        internal_date = int(msg.get("internalDate", 0))

        body_text = ""
        body_html = ""

        def _extract_parts(parts):
            nonlocal body_text, body_html
            for part in parts:
                mt = part.get("mimeType", "")
                data = part.get("body", {}).get("data", "")
                if data:
                    try:
                        decoded = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
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
                    decoded = base64.urlsafe_b64decode(raw_body + "==").decode("utf-8", errors="replace")
                    mt = payload.get("mimeType", "")
                    if mt == "text/html":
                        body_html = decoded
                    else:
                        body_text = decoded
                except Exception:
                    pass

        snippet = msg.get("snippet", "")
        label_ids = msg.get("labelIds", [])

        return {
            "id":            msg_id,
            "subject":       subject,
            "sender":        sender,
            "date":          date,
            "internal_date": internal_date,
            "snippet":       snippet,
            "body_text":     body_text[:5000],
            "body_html":     body_html[:10000],
            "label_ids":     label_ids,
            "headers_raw":   dict(headers),
        }

    except Exception as exc:
        logger.error("_get_message_async falhou para %s: %s", msg_id, exc)
        return None


# ─── Label management ─────────────────────────────────────────────

_blocked_label_id_cache: Optional[str] = None


async def _get_or_create_blocked_label(token: str) -> Optional[str]:
    """Obtém ou cria a label PHISHGUARD_BLOCKED."""
    global _blocked_label_id_cache
    if _blocked_label_id_cache:
        return _blocked_label_id_cache

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.get(
                f"{GMAIL_API_BASE}/labels",
                headers=_auth_headers(token),
            )
            r.raise_for_status()
            labels = r.json().get("labels", [])

        for label in labels:
            if label.get("name") == BLOCKED_LABEL_NAME:
                _blocked_label_id_cache = label["id"]
                return label["id"]

        # Criar label se não existir
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            r = await c.post(
                f"{GMAIL_API_BASE}/labels",
                headers={**_auth_headers(token), "Content-Type": "application/json"},
                json={
                    "name":                  BLOCKED_LABEL_NAME,
                    "labelListVisibility":   "labelShow",
                    "messageListVisibility": "show",
                },
            )
            r.raise_for_status()
            label_id = r.json().get("id")
            _blocked_label_id_cache = label_id
            logger.info("Gmail: label '%s' criada com ID: %s", BLOCKED_LABEL_NAME, label_id)
            return label_id

    except Exception as exc:
        logger.error("Erro ao gerir label PHISHGUARD_BLOCKED: %s", exc)
        return None


async def block_email_async(
    message_id: str,
    reasons: List[str] | None = None,
    score: int = 100,
) -> bool:
    """Move um email para o lixo e adiciona label PHISHGUARD_BLOCKED."""
    token = await _get_access_token_async()
    if not token:
        return False

    try:
        blocked_label_id = await _get_or_create_blocked_label(token)

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            modify_body: Dict = {
                "addLabelIds":    ["TRASH"],
                "removeLabelIds": ["INBOX"],
            }
            if blocked_label_id:
                modify_body["addLabelIds"].append(blocked_label_id)

            r = await c.post(
                f"{GMAIL_API_BASE}/messages/{message_id}/modify",
                headers={**_auth_headers(token), "Content-Type": "application/json"},
                json=modify_body,
            )
            r.raise_for_status()
            logger.info("Gmail: email %s movido para TRASH (bloqueado)", message_id)
            return True

    except Exception as exc:
        logger.error("Erro ao bloquear email %s: %s", message_id, exc)
        return False


async def unblock_email_async(message_id: str) -> bool:
    """Restaura um email do lixo para a caixa de entrada."""
    token = await _get_access_token_async()
    if not token:
        return False

    try:
        blocked_label_id = await _get_or_create_blocked_label(token)

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
            remove_labels = ["TRASH"]
            if blocked_label_id:
                remove_labels.append(blocked_label_id)

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


# ─── Análise de email individual ──────────────────────────────────

async def _analyse_single_email(
    email_data: Dict,
    auto_block: bool = True,
) -> Optional[Dict]:
    """Analisa um único email usando o motor híbrido."""
    msg_id  = email_data.get("id", "")
    subject = email_data.get("subject", "")
    sender  = email_data.get("sender", "")

    try:
        from backend.services.hybrid_analyzer import hybrid_analyze_email

        headers_str = json.dumps(email_data.get("headers_raw", {}))
        body = email_data.get("body_text") or email_data.get("body_html", "")

        result = await asyncio.wait_for(
            hybrid_analyze_email(
                sender=sender,
                headers=headers_str,
                body=body,
                run_external_apis=True,
                timeout_total=55.0,
            ),
            timeout=60.0,
        )

        score   = result.score
        verdict = result.verdict
        reasons = result.reasons
        ml_data = result.ml or {}

        blocked = False
        if auto_block and score >= 70:
            blocked = await block_email_async(msg_id, reasons, score)
            if blocked:
                reasons.insert(0, f"BLOQUEADO: score={score} — movido para o lixo")

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
                "score":   30,
                "verdict": "SUSPEITO",
                "reasons": ["analysis_timeout — verificar manualmente"],
                "blocked": False,
                "ml":      {},
            },
        }
    except Exception as exc:
        logger.error("_analyse_single_email falhou para %s: %s", msg_id, exc)
        return {
            "email": {
                "id":      msg_id,
                "subject": subject,
                "sender":  sender,
                "date":    email_data.get("date", ""),
                "snippet": email_data.get("snippet", ""),
                "internal_date": email_data.get("internal_date", 0),
            },
            "analysis": {
                "score":   30,
                "verdict": "SUSPEITO",
                "reasons": [f"Erro na análise: {type(exc).__name__} — verificar manualmente"],
                "blocked": False,
                "error":   str(exc),
                "ml":      {},
            },
        }


def _add_to_analysed_cache(result: Dict) -> None:
    """Adiciona um resultado à cache de emails analisados."""
    global _analysed_cache
    email_id = result.get("email", {}).get("id", "")

    _analysed_cache = [e for e in _analysed_cache
                       if e.get("email", {}).get("id") != email_id]

    _analysed_cache.append(result)
    _analysed_cache.sort(
        key=lambda e: e.get("email", {}).get("internal_date", 0),
        reverse=True,
    )

    if len(_analysed_cache) > 200:
        _analysed_cache = _analysed_cache[:200]

    _analysed_ids.add(email_id)


# ─── Pipeline principal ───────────────────────────────────────────

async def scan_inbox(
    max_results: int = 30,
    query: str = "",
    auto_block: bool = True,
    incremental: bool = False,
) -> List[Dict]:
    """
    Scan completo da caixa de entrada do Gmail.
    Analisa cada email e bloqueia se phishing detectado.
    """
    global _last_scan_ts, _scan_running
    _scan_running = True

    try:
        token = await _get_access_token_async()
        if not token:
            logger.error("❌ Não foi possível autenticar com a Gmail API.")
            return []

        message_ids = await _list_message_ids(token, max_results, query)
        if not message_ids:
            logger.info("Nenhum email encontrado.")
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

        semaphore = asyncio.Semaphore(10)

        async def _fetch_with_sem(mid: str) -> Optional[Dict]:
            async with semaphore:
                return await _get_message_async(token, mid)

        fetch_tasks = [_fetch_with_sem(mid) for mid in message_ids]
        email_data_list = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        analyse_sem = asyncio.Semaphore(3)

        async def _analyse_with_sem(ed: Dict) -> Optional[Dict]:
            async with analyse_sem:
                result = await _analyse_single_email(ed, auto_block=auto_block)
                if result:
                    _add_to_analysed_cache(result)
                return result

        analyse_tasks = [
            _analyse_with_sem(ed)
            for ed in email_data_list
            if isinstance(ed, dict) and ed
        ]
        if not analyse_tasks:
            return []

        results = await asyncio.gather(*analyse_tasks, return_exceptions=True)

        final: List[Dict] = []
        threats = 0
        for r in results:
            if isinstance(r, Exception):
                logger.warning("Erro num email: %s", r)
                continue
            if r is not None:
                final.append(r)
                if r.get("analysis", {}).get("score", 0) >= 60:
                    threats += 1

        _last_scan_ts = time.monotonic()
        logger.info("✅ Scan concluído: %d emails, %d ameaças", len(final), threats)
        return final
    finally:
        _scan_running = False


# ─── Background scan ─────────────────────────────────────────────

async def _background_scan(max_results: int = 30, incremental: bool = True) -> None:
    """Scan em background (não bloqueia o HTTP request)."""
    global _scan_running
    try:
        logger.info("Background scan iniciado (incremental=%s, max=%d)...",
                    incremental, max_results)
        await scan_inbox(
            max_results=max_results,
            auto_block=True,
            incremental=incremental,
        )
        logger.info("Background scan concluído. Cache: %d emails.", len(_analysed_cache))
    except Exception as exc:
        logger.error("Erro no background scan: %s", exc)
    finally:
        _scan_running = False


# ─── API pública ──────────────────────────────────────────────────

async def get_all_analysed_emails(max_results: int = 100) -> List[Dict]:
    """
    Devolve todos os emails analisados.
    Inicia scan em background se a cache estiver vazia.
    """
    global _scan_running

    cache_expired = (time.monotonic() - _last_scan_ts) > _CACHE_TTL_SECS

    if not _scan_running:
        if not _analysed_cache:
            _scan_running = True
            asyncio.create_task(_background_scan(incremental=False))
        elif cache_expired:
            _scan_running = True
            asyncio.create_task(_background_scan(incremental=True))

    return _analysed_cache[:max_results]


async def force_refresh(max_results: int = 30) -> List[Dict]:
    """Força um scan completo e aguarda o resultado."""
    global _scan_running, _analysed_ids
    if not _scan_running:
        _scan_running = True
        _analysed_ids.clear()
        logger.info("force_refresh: IDs limpos, scan completo iniciado")
        await _background_scan(max_results=max_results, incremental=False)
    return _analysed_cache[:max_results]


# ─── Emails bloqueados ────────────────────────────────────────────

async def get_blocked_emails_async(max_results: int = 50) -> List[Dict]:
    """Lista todos os emails bloqueados (com label PHISHGUARD_BLOCKED)."""
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

        tasks = [_get_message_async(token, mid) for mid in message_ids[:max_results]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        blocked = []
        for data in results:
            if isinstance(data, dict) and data:
                cached = next(
                    (e for e in _analysed_cache
                     if e.get("email", {}).get("id") == data["id"]),
                    None,
                )
                if cached:
                    blocked.append(cached)
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
                            "ml":      {},
                        },
                    })
        return blocked

    except Exception as exc:
        logger.error("Erro ao listar emails bloqueados: %s", exc)
        return []


# ─── Aliases de compatibilidade ──────────────────────────────────

async def block_email(
    message_id: str,
    reasons: List[str] | None = None,
    score: int = 100,
) -> bool:
    return await block_email_async(message_id, reasons or [], score)


async def unblock_email(message_id: str) -> bool:
    return await unblock_email_async(message_id)


async def get_blocked_emails(max_results: int = 50) -> List[Dict]:
    return await get_blocked_emails_async(max_results)
