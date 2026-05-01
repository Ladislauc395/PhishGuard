"""
backend/routers/extension_router.py
──────────────────────────────────────────────────────────────────────────────
Router da extensão Chrome PhishGuard Angola — v5.0

CORRECÇÕES v5.0:
  - Usa analyze_url() DIRECTAMENTE do url_analyzer (não orquestrador antigo)
  - Heurísticas locais melhoradas para detectar wixstudio.com, netlify.app, etc.
  - Detecção de hosting gratuito (wixstudio.com, netlify.app, github.io, etc.)
  - Score mínimo para URLs suspeitas (nunca retorna 0 para domínios de phishing conhecidos)
  - Blacklist (PhishTank/URLhaus/OpenPhish) tem prioridade máxima
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Extension"])

# ─── Imports correctos (usar url_analyzer corrigido) ─────────────

# IMPORTANTE: Usar a função analyze_url do url_analyzer (async)
try:
    from backend.services.url_analyzer import analyze_url
    _HAS_URL_ANALYZER = True
    logger.info("url_analyzer.analyze_url importado com sucesso ✓")
except ImportError as e:
    logger.error(f"FALHA ao importar url_analyzer: {e}")
    _HAS_URL_ANALYZER = False

try:
    from backend.services.external_apis import phishing_blacklist_check
    _HAS_BLACKLIST = True
    logger.info("external_apis.phishing_blacklist_check importado ✓")
except ImportError as e:
    logger.error(f"FALHA ao importar external_apis: {e}")
    _HAS_BLACKLIST = False

try:
    from backend.services.ml_url_classifier import analyze_url_with_ml
    _HAS_ML = True
    logger.info("ml_url_classifier importado ✓")
except ImportError as e:
    logger.warning(f"ml_url_classifier não disponível: {e}")
    _HAS_ML = False

try:
    from backend.core.config import settings as _cfg
    _HAS_SETTINGS = True
except ImportError:
    _cfg = None
    _HAS_SETTINGS = False

# ─── Configuração ─────────────────────────────────────────────────

_BACKEND_PUBLIC_URL = "http://10.249.221.68:8000"

# ─── Rate limiting ────────────────────────────────────────────────

_rate_limit: dict[str, list[float]] = {}
_RATE_WINDOW = 60.0
_RATE_MAX = 60


def _check_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    hits = [t for t in _rate_limit.get(ip, []) if now - t < _RATE_WINDOW]
    if len(hits) >= _RATE_MAX:
        _rate_limit[ip] = hits
        return False
    hits.append(now)
    _rate_limit[ip] = hits
    return True


# ─── Cache de resultados (TTL 10 min) ────────────────────────────

_result_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 600.0


def _cache_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def _cache_get(url: str) -> Optional[dict]:
    k = _cache_key(url)
    entry = _result_cache.get(k)
    if not entry:
        return None
    if time.monotonic() - entry[0] > _CACHE_TTL:
        del _result_cache[k]
        return None
    return entry[1]


def _cache_set(url: str, result: dict) -> None:
    k = _cache_key(url)
    _result_cache[k] = (time.monotonic(), result)
    if len(_result_cache) > 2000:
        oldest = sorted(_result_cache, key=lambda x: _result_cache[x][0])[:500]
        for o in oldest:
            del _result_cache[o]


# ─── Estatísticas ─────────────────────────────────────────────────

_stats: dict = {
    "total_checks": 0,
    "phishing_found": 0,
    "suspicious": 0,
    "safe": 0,
    "cache_hits": 0,
    "api_errors": 0,
    "blacklist_hits": 0,
    "ml_detections": 0,
    "started_at": datetime.now(tz=timezone.utc).isoformat(),
}

# ─── Modelos Pydantic ─────────────────────────────────────────────

class CheckUrlRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL não pode ser vazia")
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError("URL inválida — sem hostname")
        except Exception as exc:
            raise ValueError(f"URL inválida: {exc}")
        return v


class CheckUrlsRequest(BaseModel):
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: List[str]) -> List[str]:
        if len(v) > 20:
            raise ValueError("Máximo 20 URLs por batch")
        return [u.strip() for u in v if u.strip()]


# ─── Heurísticas locais MELHORADAS v5.0 ───────────────────────────

_SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".click", ".download", ".loan", ".work", ".win",
    ".cam", ".icu", ".surf", ".monster", ".live", ".online",
    ".site", ".website", ".press", ".space", ".fun", ".host",
    ".shop", ".store", ".vip", ".bid", ".stream",
}

# Hosting gratuito SUSPEITO (muito usado em phishing)
_SUSPICIOUS_HOSTING = {
    "wixstudio.com", "wixsite.com", "wix.com",
    "netlify.app", "netlify.com",
    "github.io", "github.com",
    "vercel.app", "pages.dev",
    "glitch.me", "replit.co",
    "000webhost.com", "000webhostapp.com",
    "weebly.com", "webs.com",
    "firebaseapp.com", "web.app",
    "herokuapp.com", "ngrok.io", "ngrok-free.app",
}

_BANK_KEYWORDS = {
    "multicaixa", "bai", "bfa", "bca", "unitel", "bna",
    "angola", "kwanza", "atlantico", "standard", "emis",
    "paypal", "apple", "google", "microsoft", "amazon",
    "netflix", "dhl", "fedex", "banco", "bank",
}

_ACTION_KEYWORDS = {
    "login", "signin", "account", "verify", "confirm",
    "secure", "update", "password", "reset", "wallet",
    "banking", "payment", "credential", "validate",
    "activate", "blocked", "suspended", "verify-now",
    "confirm-identity", "security-check",
}


def _local_heuristics(url: str) -> tuple[int, list[str]]:
    """Heurísticas locais melhoradas - detecta hosting gratuito suspeito."""
    score = 0
    reasons: list[str] = []

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        full = url.lower()
        path = (parsed.path or "").lower()
    except Exception:
        return 0, []

    # HTTP não seguro
    if url.startswith("http://"):
        score += 15
        reasons.append("Ligação HTTP não encriptada (MITM risk)")

    # IP directo
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 40
        reasons.append("Endereço IP usado directamente como URL")

    # TLD suspeito
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 25
            reasons.append(f"TLD suspeito: {tld}")
            break

    # ⭐ HOSTING GRATUITO SUSPEITO (NOVO - detecta wixstudio.com)
    for h in _SUSPICIOUS_HOSTING:
        if h in host:
            score += 35
            reasons.append(f"Hosting gratuito frequentemente usado em phishing: {h}")
            break

    # Símbolo '@' na URL (credential harvesting)
    if "@" in (parsed.path or "") or "@" in (parsed.netloc or ""):
        score += 35
        reasons.append("Símbolo '@' detectado na URL (possível credential harvesting)")

    # Muitos hífens no domínio
    if host.count("-") >= 3:
        score += 15
        reasons.append(f"Domínio com {host.count('-')} hífens (suspeito)")

    # Domínio muito longo
    if len(host) > 45:
        score += 15
        reasons.append(f"Domínio anormalmente longo ({len(host)} caracteres)")

    # Combinação de marca bancária + acção (phishing clássico)
    has_bank = any(k in full for k in _BANK_KEYWORDS)
    has_action = any(k in full for k in _ACTION_KEYWORDS)
    if has_bank and has_action:
        score += 30
        reasons.append("URL combina marca com acção de autenticação (phishing típico)")

    # Muitos subdomínios
    parts = host.split(".")
    if len(parts) > 4:
        score += 10
        reasons.append(f"Muitos subdomínios ({len(parts) - 2} níveis)")

    # Palavras de phishing no path
    phishing_path_words = [
        "login", "signin", "account", "verify", "confirm",
        "secure", "update", "banking", "password",
    ]
    found_words = [w for w in phishing_path_words if w in path]
    if len(found_words) >= 2:
        score += 20
        reasons.append(f"Palavras de phishing no path: {', '.join(found_words[:3])}")

    return min(100, score), reasons


# ─── Wrappers seguros ─────────────────────────────────────────────

async def _safe_analyze_url(url: str) -> dict:
    """Usa a função analyze_url do url_analyzer (versão corrigida v8)."""
    if not _HAS_URL_ANALYZER:
        # Fallback: heurísticas locais apenas
        h_score, h_reasons = _local_heuristics(url)
        score = h_score
        reasons = h_reasons
        if not reasons:
            reasons = ["url_analyzer_indisponível"]
    else:
        try:
            result = await asyncio.wait_for(analyze_url(url), timeout=30.0)
            score = result.get("score", 0)
            reasons = result.get("reasons", [])
        except asyncio.TimeoutError:
            logger.warning(f"analyze_url timeout para {url[:60]}")
            h_score, h_reasons = _local_heuristics(url)
            score = h_score
            reasons = h_reasons + ["analysis_timeout"]
        except Exception as e:
            logger.error(f"analyze_url falhou para {url[:60]}: {e}")
            h_score, h_reasons = _local_heuristics(url)
            score = h_score
            reasons = h_reasons + [f"analysis_error: {type(e).__name__}"]

    return {"score": score, "reasons": reasons}


async def _safe_blacklists(url: str) -> dict:
    """Verifica blacklists (PhishTank/URLhaus/OpenPhish) com timeout."""
    if not _HAS_BLACKLIST:
        return {"blacklisted": False, "score": 0, "reasons": []}

    try:
        result = await asyncio.wait_for(phishing_blacklist_check(url), timeout=15.0)
        return result
    except asyncio.TimeoutError:
        logger.warning(f"Blacklist timeout para {url[:60]}")
        return {"blacklisted": False, "score": 0, "reasons": ["blacklist_timeout"]}
    except Exception as e:
        logger.warning(f"Blacklist falhou para {url[:60]}: {e}")
        return {"blacklisted": False, "score": 0, "reasons": [f"blacklist_error: {type(e).__name__}"]}


async def _safe_ml(url: str) -> dict:
    """ML URL classifier com timeout."""
    if not _HAS_ML:
        return {"ml_score": 0, "reasons": []}

    try:
        result = await asyncio.wait_for(analyze_url_with_ml(url), timeout=10.0)
        return result
    except asyncio.TimeoutError:
        logger.debug(f"ML timeout para {url[:60]}")
        return {"ml_score": 0, "reasons": ["ml_timeout"]}
    except Exception as e:
        logger.debug(f"ML falhou para {url[:60]}: {e}")
        return {"ml_score": 0, "reasons": []}


# ─── Pipeline principal de análise v5.0 ──────────────────────────

async def _analyze_url_v5(url: str) -> dict:
    """
    Pipeline v5.0:
      1. Cache
      2. Heurísticas locais (rápidas)
      3. Blacklists (PhishTank/URLhaus/OpenPhish) - PRIORIDADE MÁXIMA
      4. ML URL classifier
      5. analyze_url (completo)
      6. Score final com lógica de máximo
    """
    cached = _cache_get(url)
    if cached:
        _stats["cache_hits"] += 1
        return {**cached, "cached": True}

    t0 = time.monotonic()

    # 1. Heurísticas locais (rápidas)
    h_score, h_reasons = _local_heuristics(url)

    # 2. Blacklists em paralelo com ML e analyze_url
    bl_task = _safe_blacklists(url)
    ml_task = _safe_ml(url)
    analyzer_task = _safe_analyze_url(url)

    bl_result, ml_result, analyzer_result = await asyncio.gather(
        bl_task, ml_task, analyzer_task
    )

    bl_score = bl_result.get("score", 0)
    bl_blacklisted = bl_result.get("blacklisted", False)
    bl_reasons = bl_result.get("reasons", [])

    ml_score = ml_result.get("ml_score", 0)
    ml_reasons = ml_result.get("reasons", [])

    analyzer_score = analyzer_result.get("score", 0)
    analyzer_reasons = analyzer_result.get("reasons", [])

    # ⭐ PRIORIDADE MÁXIMA: Blacklist confirmada
    if bl_blacklisted:
        final_score = max(bl_score, 85)
        reasons = bl_reasons.copy()
        logger.info(f"BLACKLIST HIT: {url[:60]} → score={final_score}")
        _stats["blacklist_hits"] += 1
    else:
        # Média ponderada
        weighted = (
            h_score * 0.20 +      # heurísticas locais
            ml_score * 0.25 +     # ML
            analyzer_score * 0.35 +  # analyze_url (contém WHOIS, crawler, etc.)
            bl_score * 0.20       # blacklist score (mesmo sem confirmado)
        )
        final_score = int(max(weighted, h_score, ml_score, analyzer_score, bl_score))
        reasons = list(dict.fromkeys(h_reasons + ml_reasons + analyzer_reasons + bl_reasons))

    final_score = min(100, max(0, final_score))

    # Se score baixo mas hosting suspeito, aumentar ligeiramente
    if final_score < 30 and any(h in url.lower() for h in _SUSPICIOUS_HOSTING):
        final_score = max(final_score, 25)
        if "hosting_suspeito" not in str(reasons):
            reasons.append("Domínio em hosting gratuito frequentemente usado em phishing")

    verdict = (
        "NÃO SEGURO" if final_score >= 60
        else ("SUSPEITO" if final_score >= 30
              else "SEGURO")
    )

    elapsed = time.monotonic() - t0
    try:
        host_label = urlparse(url).hostname or url
    except Exception:
        host_label = url

    logger.info(
        "Check v5: %s → %d (%s) | h=%d ml=%d analyzer=%d bl=%d | %.2fs",
        host_label, final_score, verdict,
        h_score, ml_score, analyzer_score, bl_score, elapsed,
    )

    _stats["total_checks"] += 1
    if final_score >= 60:
        _stats["phishing_found"] += 1
    elif final_score >= 30:
        _stats["suspicious"] += 1
    else:
        _stats["safe"] += 1

    # Actualizar estatísticas de ML
    if ml_score >= 60:
        _stats["ml_detections"] += 1

    result = {
        "url": url,
        "score": final_score,
        "verdict": verdict,
        "reasons": reasons[:15],  # limitar razões
        "cached": False,
        "blacklisted": bl_blacklisted,
        "ml_score": ml_score,
        "details": {
            "heuristic_score": h_score,
            "ml_score": ml_score,
            "analyzer_score": analyzer_score,
            "blacklist_score": bl_score,
            "elapsed_seconds": round(elapsed, 2),
            "pipeline_version": "5.0",
        },
    }

    _cache_set(url, result)
    return result


# ─── CORS helpers ─────────────────────────────────────────────────

def _cors() -> dict:
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }


# ─── Endpoints ────────────────────────────────────────────────────

@router.options("/check-url")
@router.options("/check-urls-batch")
async def options_preflight():
    return JSONResponse(content={}, headers=_cors())


@router.post("/check-url")
async def check_url_endpoint(body: CheckUrlRequest, request: Request):
    """Verificar uma URL individual — pipeline v5.0."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit excedido. Aguarde 1 minuto.")

    try:
        result = await _analyze_url_v5(body.url)
        return JSONResponse(content=result, headers=_cors())
    except Exception as exc:
        logger.error(f"Erro em /check-url: {exc}", exc_info=True)
        return JSONResponse(
            content={
                "url": body.url,
                "score": 0,
                "verdict": "ERRO",
                "reasons": [f"Erro interno: {str(exc)[:100]}"],
                "error": str(exc),
                "cached": False,
            },
            headers=_cors(),
        )


@router.post("/check-urls-batch")
async def check_urls_batch(body: CheckUrlsRequest, request: Request):
    """Verificar até 20 URLs em paralelo."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit excedido.")

    async def _safe_check(url: str):
        try:
            return url, await _analyze_url_v5(url)
        except Exception as exc:
            logger.warning(f"Batch falhou para {url}: {exc}")
            return url, {
                "url": url,
                "score": 0,
                "verdict": "SEGURO",
                "reasons": [f"Erro: {str(exc)[:50]}"],
                "cached": False,
                "blacklisted": False,
            }

    results = await asyncio.gather(*[_safe_check(u) for u in body.urls[:20]])
    return JSONResponse(content=dict(results), headers=_cors())


@router.get("/stats")
async def get_stats():
    """Estatísticas de uso da extensão."""
    return JSONResponse(
        content={
            **_stats,
            "cache_size": len(_result_cache),
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        },
        headers=_cors(),
    )


@router.get("/status")
async def extension_status():
    """Estado completo da integração extensão ↔ backend."""
    def _key_ok(*attrs: str) -> str:
        if not _HAS_SETTINGS or _cfg is None:
            return "settings_unavailable"
        for attr in attrs:
            if getattr(_cfg, attr, None):
                return "configured"
        return "no_api_key"

    apis_status = {
        "url_analyzer": "configured" if _HAS_URL_ANALYZER else "unavailable",
        "blacklist": "configured" if _HAS_BLACKLIST else "unavailable",
        "ml_classifier": "configured" if _HAS_ML else "not_installed",
        "virustotal": _key_ok("VIRUSTOTAL_API_KEY"),
        "safe_browsing": _key_ok("GOOGLE_SAFE_BROWSING_API_KEY"),
        "abuseipdb": _key_ok("ABUSEIPDB_API_KEY"),
    }

    return JSONResponse(
        content={
            "backend_url": _BACKEND_PUBLIC_URL,
            "check_url_endpoint": f"{_BACKEND_PUBLIC_URL}/extension/check-url",
            "backend_online": True,
            "apis_status": apis_status,
            "total_checks": _stats["total_checks"],
            "phishing_blocked": _stats["phishing_found"],
            "blacklist_hits": _stats["blacklist_hits"],
            "ml_detections": _stats["ml_detections"],
            "cache_entries": len(_result_cache),
            "pipeline_version": "5.0",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        },
        headers=_cors(),
    )


@router.get("/health")
async def extension_health():
    """Health check rápido."""
    return JSONResponse(
        content={
            "status": "ok",
            "version": "5.0.0",
            "pipeline": "heuristics + blacklist + ml + analyzer",
            "has_url_analyzer": _HAS_URL_ANALYZER,
            "has_blacklist": _HAS_BLACKLIST,
            "has_ml": _HAS_ML,
            "cache_entries": len(_result_cache),
            "stats": _stats,
        },
        headers=_cors(),
    )