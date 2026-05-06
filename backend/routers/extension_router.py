"""
backend/routers/extension_router.py
──────────────────────────────────────────────────────────────────────────────
Router da extensão Chrome PhishGuard Angola — v5.3

CORRECÇÕES v5.3:
- CORRIGIDO: Se analyze_url retorna score ≤ 10 OU "trusted_domain" OU "no_threats_detected",
  o resultado é SEGURO (score 5), IGNORANDO completamente ML e blacklists
- CORRIGIDO: ML score só é usado se ≥ 60 (phishing confirmado)
- CORRIGIDO: Blacklist só se sobrepõe se "blacklisted" = True
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Extension"])

try:
    from backend.services.url_analyzer import analyze_url
    _HAS_URL_ANALYZER = True
except ImportError:
    _HAS_URL_ANALYZER = False

try:
    from backend.services.external_apis import phishing_blacklist_check
    _HAS_BLACKLIST = True
except ImportError:
    _HAS_BLACKLIST = False

try:
    from backend.services.ml_url_classifier import analyze_url_with_ml
    _HAS_ML = True
except ImportError:
    _HAS_ML = False

_BACKEND_PUBLIC_URL = "http://10.26.54.68:8000"

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

_stats: dict = {
    "total_checks": 0, "phishing_found": 0, "suspicious": 0, "safe": 0,
    "cache_hits": 0, "blacklist_hits": 0, "ml_detections": 0,
    "started_at": datetime.now(tz=timezone.utc).isoformat(),
}

class CheckUrlRequest(BaseModel):
    url: str
    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v: raise ValueError("URL não pode ser vazia")
        if not v.startswith(("http://", "https://")): v = f"https://{v}"
        if not urlparse(v).netloc: raise ValueError("URL inválida")
        return v

class CheckUrlsRequest(BaseModel):
    urls: List[str]
    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: List[str]) -> List[str]:
        if len(v) > 20: raise ValueError("Máximo 20 URLs")
        return [u.strip() for u in v if u.strip()]

# ═══════════════════════════════════════════════════════════════════
# PIPELINE v5.3 — CORRIGIDA
# ═══════════════════════════════════════════════════════════════════

async def _analyze_url_v5(url: str) -> dict:
    cached = _cache_get(url)
    if cached:
        _stats["cache_hits"] += 1
        _stats["total_checks"] += 1
        return {**cached, "cached": True}

    t0 = time.monotonic()

    # 1. analyze_url (pipeline principal)
    analyzer_score = 0
    analyzer_reasons: list[str] = []
    if _HAS_URL_ANALYZER:
        try:
            r = await asyncio.wait_for(analyze_url(url), timeout=30.0)
            analyzer_score = r.get("score", 0)
            analyzer_reasons = r.get("reasons", [])
        except:
            analyzer_reasons = ["analysis_timeout"]

    # 2. Blacklists
    bl_blacklisted = False
    bl_score = 0
    bl_reasons: list[str] = []
    if _HAS_BLACKLIST:
        try:
            bl = await asyncio.wait_for(phishing_blacklist_check(url), timeout=15.0)
            bl_blacklisted = bl.get("blacklisted", False)
            bl_score = bl.get("score", 0)
            bl_reasons = bl.get("reasons", [])
        except:
            pass

    # 3. ML
    ml_score = 0
    ml_reasons: list[str] = []
    if _HAS_ML:
        try:
            ml = await asyncio.wait_for(analyze_url_with_ml(url), timeout=10.0)
            ml_score = ml.get("ml_score", 0)
            ml_reasons = ml.get("reasons", [])
        except:
            pass

    # ═══════════════════════════════════════════════════════════════
    # DECISÃO FINAL v5.3
    # ═══════════════════════════════════════════════════════════════
    
    # REGRA 1: Blacklist CONFIRMADA → phishing
    if bl_blacklisted:
        final_score = max(bl_score, 85)
        reasons = bl_reasons
        _stats["blacklist_hits"] += 1
    
    # REGRA 2: analyze_url diz SEGURO (score ≤ 10 ou trusted_domain ou no_threats_detected)
    # → IGNORA completamente ML e blacklists não confirmadas
    elif (analyzer_score <= 10 or 
          "trusted_domain" in analyzer_reasons or 
          "no_threats_detected" in analyzer_reasons):
        final_score = 5
        reasons = ["no_threats_detected"]
    
    # REGRA 3: ML confirma phishing (≥ 60) → usar score do ML
    elif ml_score >= 60:
        final_score = ml_score
        reasons = ml_reasons + analyzer_reasons
        _stats["ml_detections"] += 1
    
    # REGRA 4: Nenhum sinal forte → SEGURO
    else:
        # Se analyzer deu algo entre 11-59 e ML deu < 60
        # Mas se ambos são baixos → SEGURO
        if analyzer_score < 30 and ml_score < 60:
            final_score = 5
            reasons = ["no_threats_detected"]
        else:
            final_score = max(analyzer_score, ml_score, bl_score)
            reasons = list(dict.fromkeys(analyzer_reasons + ml_reasons + bl_reasons))
            if final_score < 30:
                final_score = 5
                reasons = ["no_threats_detected"]

    final_score = min(100, max(0, final_score))

    if final_score >= 60:
        verdict = "NÃO SEGURO"
    elif final_score >= 30:
        verdict = "SUSPEITO"
    else:
        verdict = "SEGURO"

    elapsed = time.monotonic() - t0

    logger.info(
        "Check v5.3: %s → %d (%s) | analyzer=%d ml=%d bl=%d | %.2fs",
        urlparse(url).hostname or url, final_score, verdict,
        analyzer_score, ml_score, bl_score, elapsed,
    )

    _stats["total_checks"] += 1
    if final_score >= 60: _stats["phishing_found"] += 1
    elif final_score >= 30: _stats["suspicious"] += 1
    else: _stats["safe"] += 1

    result = {
        "url": url, "score": final_score, "verdict": verdict,
        "reasons": reasons[:15], "cached": False,
        "blacklisted": bl_blacklisted, "ml_score": ml_score,
        "details": {
            "analyzer_score": analyzer_score, "ml_score": ml_score,
            "blacklist_score": bl_score, "elapsed_seconds": round(elapsed, 2),
            "pipeline_version": "5.3",
        },
    }
    _cache_set(url, result)
    return result


def _cors():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }

@router.options("/check-url")
@router.options("/check-urls-batch")
async def options_preflight():
    return JSONResponse(content={}, headers=_cors())

@router.post("/check-url")
async def check_url_endpoint(body: CheckUrlRequest, request: Request):
    if not _check_rate_limit(request.client.host if request.client else "unknown"):
        raise HTTPException(status_code=429, detail="Rate limit excedido.")
    try:
        result = await _analyze_url_v5(body.url)
        return JSONResponse(content=result, headers=_cors())
    except Exception as exc:
        return JSONResponse(content={
            "url": body.url, "score": 0, "verdict": "ERRO",
            "reasons": [f"Erro: {str(exc)[:100]}"], "cached": False,
        }, headers=_cors())

@router.post("/check-urls-batch")
async def check_urls_batch(body: CheckUrlsRequest, request: Request):
    if not _check_rate_limit(request.client.host if request.client else "unknown"):
        raise HTTPException(status_code=429, detail="Rate limit excedido.")
    async def _safe_check(url):
        try: return url, await _analyze_url_v5(url)
        except: return url, {"url": url, "score": 0, "verdict": "ERRO", "reasons": ["Erro"], "cached": False}
    results = await asyncio.gather(*[_safe_check(u) for u in body.urls[:20]])
    return JSONResponse(content=dict(results), headers=_cors())

@router.get("/stats")
async def get_stats():
    return JSONResponse(content={**_stats, "cache_size": len(_result_cache), "timestamp": datetime.now(tz=timezone.utc).isoformat()}, headers=_cors())

@router.get("/status")
async def extension_status():
    def _key_ok(attr):
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
    return JSONResponse(content={
        "backend_url": _BACKEND_PUBLIC_URL, "check_url_endpoint": f"{_BACKEND_PUBLIC_URL}/extension/check-url",
        "backend_online": True, "apis_status": apis_status, "apis_configured": apis_configured,
        "apis_total": len(apis_status), "total_checks": _stats["total_checks"],
        "phishing_blocked": _stats["phishing_found"], "blacklist_hits": _stats["blacklist_hits"],
        "ml_detections": _stats["ml_detections"], "cache_entries": len(_result_cache),
        "pipeline_version": "5.3", "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }, headers=_cors())

@router.get("/health")
async def extension_health():
    return JSONResponse(content={
        "status": "ok", "version": "5.3.0", "pipeline": "unified-v5.3",
        "has_url_analyzer": _HAS_URL_ANALYZER, "has_blacklist": _HAS_BLACKLIST,
        "has_ml": _HAS_ML, "cache_entries": len(_result_cache), "stats": _stats,
    }, headers=_cors())

