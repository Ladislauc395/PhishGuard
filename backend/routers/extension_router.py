"""
backend/routers/extension_router.py
──────────────────────────────────────────────────────────────────────────────
Router da extensão Chrome PhishGuard Angola — v5.2

CORRECÇÕES v5.2:
  - Usa analyze_url() do url_analyzer.py DIRETAMENTE (mesma pipeline do app)
  - Scores CONSISTENTES entre app (Threats) e extensão Chrome
  - PhishTank integrado via phishing_blacklist_check()
  - Heurísticas locais só como complemento, não substituem o analyzer
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

# ─── Imports ──────────────────────────────────────────────────────

try:
    from backend.services.url_analyzer import analyze_url
    _HAS_URL_ANALYZER = True
    logger.info("✅ url_analyzer.analyze_url importado")
except ImportError as e:
    logger.error(f"❌ url_analyzer não disponível: {e}")
    _HAS_URL_ANALYZER = False

try:
    from backend.services.external_apis import phishing_blacklist_check, combined_url_reputation
    _HAS_BLACKLIST = True
    logger.info("✅ external_apis importado")
except ImportError as e:
    logger.error(f"❌ external_apis não disponível: {e}")
    _HAS_BLACKLIST = False

try:
    from backend.services.ml_url_classifier import analyze_url_with_ml
    _HAS_ML = True
    logger.info("✅ ml_url_classifier importado")
except ImportError as e:
    logger.warning(f"⚠️ ml_url_classifier não disponível: {e}")
    _HAS_ML = False

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

# ─── Pipeline principal UNIFICADO v5.2 ───────────────────────────

async def _analyze_url_v5(url: str) -> dict:
    """
    Pipeline UNIFICADA v5.2:
    - Usa analyze_url() do url_analyzer.py (MESMA pipeline do app Threats)
    - Complementa com blacklists e ML
    - Scores CONSISTENTES entre app e extensão
    """
    # Cache
    cached = _cache_get(url)
    if cached:
        _stats["cache_hits"] += 1
        _stats["total_checks"] += 1
        return {**cached, "cached": True}

    t0 = time.monotonic()

    # 1. Usar analyze_url() do url_analyzer.py (PIPELINE PRINCIPAL)
    analyzer_score = 0
    analyzer_reasons: list[str] = []
    
    if _HAS_URL_ANALYZER:
        try:
            analyzer_result = await asyncio.wait_for(analyze_url(url), timeout=30.0)
            analyzer_score = analyzer_result.get("score", 0)
            analyzer_reasons = analyzer_result.get("reasons", [])
            logger.info(f"analyze_url: {url[:60]} → score={analyzer_score}")
        except asyncio.TimeoutError:
            logger.warning(f"analyze_url timeout: {url[:60]}")
            analyzer_reasons = ["analysis_timeout"]
        except Exception as e:
            logger.error(f"analyze_url error: {e}")
            analyzer_reasons = [f"analysis_error: {type(e).__name__}"]

    # 2. Blacklists em paralelo
    bl_task = _safe_blacklists(url) if _HAS_BLACKLIST else _empty_blacklist()
    ml_task = _safe_ml(url) if _HAS_ML else _empty_ml()

    bl_result, ml_result = await asyncio.gather(bl_task, ml_task)

    bl_score = bl_result.get("score", 0)
    bl_blacklisted = bl_result.get("blacklisted", False)
    bl_reasons = bl_result.get("reasons", [])

    ml_score = ml_result.get("ml_score", 0)
    ml_reasons = ml_result.get("reasons", [])

    # 3. Combinar scores (PRIORIDADE: blacklist > analyzer > ML)
    if bl_blacklisted:
        final_score = max(bl_score, 85)
        reasons = bl_reasons.copy()
        _stats["blacklist_hits"] += 1
        logger.warning(f"🚨 BLACKLIST HIT: {url[:60]} → score={final_score}")
    else:
        # Média ponderada: analyzer tem peso maior
        weighted = (
            analyzer_score * 0.50 +  # url_analyzer (pipeline completa)
            ml_score * 0.25 +        # ML classifier
            bl_score * 0.25          # blacklist score
        )
        final_score = int(max(weighted, analyzer_score, ml_score, bl_score))
        reasons = list(dict.fromkeys(analyzer_reasons + ml_reasons + bl_reasons))

    final_score = min(100, max(0, final_score))

    # Se analyzer confirmou trusted_domain, garantir score baixo
    if "trusted_domain" in analyzer_reasons and not bl_blacklisted:
        final_score = min(final_score, 10)

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
        "Check v5.2: %s → %d (%s) | analyzer=%d ml=%d bl=%d | %.2fs",
        host_label, final_score, verdict,
        analyzer_score, ml_score, bl_score, elapsed,
    )

    _stats["total_checks"] += 1
    if final_score >= 60:
        _stats["phishing_found"] += 1
    elif final_score >= 30:
        _stats["suspicious"] += 1
    else:
        _stats["safe"] += 1

    if ml_score >= 60:
        _stats["ml_detections"] += 1

    result = {
        "url": url,
        "score": final_score,
        "verdict": verdict,
        "reasons": reasons[:15],
        "cached": False,
        "blacklisted": bl_blacklisted,
        "ml_score": ml_score,
        "details": {
            "analyzer_score": analyzer_score,
            "ml_score": ml_score,
            "blacklist_score": bl_score,
            "elapsed_seconds": round(elapsed, 2),
            "pipeline_version": "5.2-unified",
        },
    }

    _cache_set(url, result)
    return result


async def _safe_blacklists(url: str) -> dict:
    """Verifica blacklists com timeout."""
    try:
        result = await asyncio.wait_for(phishing_blacklist_check(url), timeout=15.0)
        return result
    except asyncio.TimeoutError:
        return {"blacklisted": False, "score": 0, "reasons": ["blacklist_timeout"]}
    except Exception as e:
        return {"blacklisted": False, "score": 0, "reasons": [f"blacklist_error: {type(e).__name__}"]}


async def _safe_ml(url: str) -> dict:
    """ML URL classifier com timeout."""
    try:
        result = await asyncio.wait_for(analyze_url_with_ml(url), timeout=10.0)
        return result
    except asyncio.TimeoutError:
        return {"ml_score": 0, "reasons": ["ml_timeout"]}
    except Exception:
        return {"ml_score": 0, "reasons": []}


def _empty_blacklist() -> dict:
    return {"blacklisted": False, "score": 0, "reasons": ["blacklist_unavailable"]}


def _empty_ml() -> dict:
    return {"ml_score": 0, "reasons": ["ml_unavailable"]}


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
    """Verificar uma URL individual — pipeline unificada v5.2."""
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
    def _key_ok(attr: str) -> str:
        from backend.core.config import settings
        return "configured" if getattr(settings, attr, None) else "no_api_key"

    apis_status = {
        "url_analyzer": "configured" if _HAS_URL_ANALYZER else "unavailable",
        "blacklist": "configured" if _HAS_BLACKLIST else "unavailable",
        "ml_classifier": "configured" if _HAS_ML else "not_installed",
        "virustotal": _key_ok("VIRUSTOTAL_API_KEY"),
        "safe_browsing": _key_ok("GOOGLE_SAFE_BROWSING_API_KEY"),
    }

    apis_configured = sum(1 for v in apis_status.values() if v == "configured")

    return JSONResponse(
        content={
            "backend_url": _BACKEND_PUBLIC_URL,
            "check_url_endpoint": f"{_BACKEND_PUBLIC_URL}/extension/check-url",
            "backend_online": True,
            "apis_status": apis_status,
            "apis_configured": apis_configured,
            "apis_total": len(apis_status),
            "total_checks": _stats["total_checks"],
            "phishing_blocked": _stats["phishing_found"],
            "blacklist_hits": _stats["blacklist_hits"],
            "ml_detections": _stats["ml_detections"],
            "cache_entries": len(_result_cache),
            "chrome_store_available": False,
            "chrome_store_url": "",
            "pipeline_version": "5.2-unified",
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
            "version": "5.2.0",
            "pipeline": "unified-url-analyzer + blacklist + ml",
            "has_url_analyzer": _HAS_URL_ANALYZER,
            "has_blacklist": _HAS_BLACKLIST,
            "has_ml": _HAS_ML,
            "cache_entries": len(_result_cache),
            "stats": _stats,
        },
        headers=_cors(),
    )
