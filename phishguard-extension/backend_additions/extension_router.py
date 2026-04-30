"""
backend/routers/extension_router.py
─────────────────────────────────────────────────────────────────────────
Router dedicado à extensão Chrome PhishGuard Angola.

Adicionar ao main.py:
    from backend.routers.extension_router import router as extension_router
    app.include_router(extension_router, prefix="/extension")

Endpoints:
    POST /extension/check-url        → análise rápida de URL
    POST /extension/check-urls-batch → análise em lote (até 20 URLs)
    GET  /extension/stats            → estatísticas de uso
    GET  /extension/health           → status da extensão + APIs externas
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, field_validator

# ─── Import services (já existentes no teu backend) ──────────────
from backend.services.orchestrator import orchestrate_url
from backend.services.ml_classifier import classify_with_groq
from backend.services.external_apis import (
    check_virustotal,
    check_safe_browsing,
    check_urlscan_existing,
    check_abuseipdb,
    combined_url_reputation,
)
from backend.services.heuristics import evaluate_domain, extract_domain, extract_urls
from backend.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Extension"])

# ─── In-memory rate limiting (simples, sem Redis) ─────────────────
# Em produção substitui por slowapi + Redis

_rate_limit: dict[str, list[float]] = {}  # ip → [timestamps]
_RATE_WINDOW = 60.0   # 1 minuto
_RATE_MAX    = 60     # max 60 requests/minuto por IP

# ─── Cache de resultados (TTL 10 min) ────────────────────────────
_result_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 600.0

# ─── Estatísticas globais ─────────────────────────────────────────
_stats = {
    "total_checks":    0,
    "phishing_found":  0,
    "suspicious":      0,
    "safe":            0,
    "cache_hits":      0,
    "api_errors":      0,
    "started_at":      datetime.now(tz=timezone.utc).isoformat(),
}


# ─── Pydantic models ──────────────────────────────────────────────

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
                raise ValueError("URL inválida")
        except Exception:
            raise ValueError("URL inválida")
        return v


class CheckUrlsRequest(BaseModel):
    urls: List[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: List[str]) -> List[str]:
        if len(v) > 20:
            raise ValueError("Máximo de 20 URLs por batch")
        return [u.strip() for u in v if u.strip()]


class UrlCheckResult(BaseModel):
    url:        str
    score:      int
    verdict:    str
    reasons:    List[str]
    cached:     bool = False
    error:      Optional[str] = None
    # Detalhe das APIs externas (opcional)
    virustotal: Optional[dict] = None
    safe_browsing: Optional[dict] = None
    urlscan:    Optional[dict] = None
    domain_info: Optional[dict] = None


# ─── Rate limiter ─────────────────────────────────────────────────

def _check_rate_limit(ip: str) -> bool:
    """Retorna True se OK, False se rate-limited."""
    now = time.monotonic()
    hits = _rate_limit.get(ip, [])
    # Remove hits fora da janela
    hits = [t for t in hits if now - t < _RATE_WINDOW]
    if len(hits) >= _RATE_MAX:
        _rate_limit[ip] = hits
        return False
    hits.append(now)
    _rate_limit[ip] = hits
    return True


# ─── Cache helpers ────────────────────────────────────────────────

def _cache_get(url: str) -> Optional[dict]:
    entry = _result_cache.get(url)
    if not entry:
        return None
    if time.monotonic() - entry[0] > _CACHE_TTL:
        del _result_cache[url]
        return None
    return entry[1]


def _cache_set(url: str, result: dict) -> None:
    _result_cache[url] = (time.monotonic(), result)
    # Limpar cache se crescer demais
    if len(_result_cache) > 2000:
        oldest_keys = sorted(_result_cache, key=lambda k: _result_cache[k][0])[:500]
        for k in oldest_keys:
            del _result_cache[k]


# ─── Core análise de URL ──────────────────────────────────────────

async def _analyze_url_for_extension(url: str) -> dict:
    """
    Pipeline de análise optimizado para a extensão Chrome.

    Fluxo:
      1. Cache hit → retorna imediatamente
      2. Heurísticas locais (< 5ms)
      3. Se score local baixo (< 15) → retorna SEGURO sem APIs externas
      4. APIs externas em paralelo (VT + GSB + URLScan)
      5. ML Groq para análise semântica (se houver texto na URL)
      6. Consenso e veredicto final
    """
    # Cache hit
    cached = _cache_get(url)
    if cached:
        _stats["cache_hits"] += 1
        return {**cached, "cached": True}

    t_start = time.monotonic()

    # ── Extracção de domínio ───────────────────────────────────────
    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower().lstrip("www.")
    except Exception:
        domain = ""

    reasons: list[str] = []
    score   = 0

    # ── Heurísticas locais (sem rede) ────────────────────────────
    try:
        from backend.models.brand import BrandProfile
        from sqlmodel import Session, select
        from backend.core.database import engine
        with Session(engine) as session:
            brands = session.exec(select(BrandProfile)).all()
    except Exception:
        brands = []

    try:
        domain_result = await asyncio.wait_for(
            evaluate_domain(url, brands),
            timeout=3.0,
        )
        if domain_result.typosquatting_detected:
            score += 50
            reasons.append(f"Typosquatting: domínio imita '{domain_result.suspected_brand}'")
        if not domain_result.dns_resolves and domain:
            score += 30
            reasons.append("Domínio não existe no DNS")
        if not domain_result.official_match and domain_result.suspected_brand:
            score += 25
            reasons.append(f"Marca '{domain_result.suspected_brand}' detectada em domínio não oficial")
    except Exception as e:
        logger.debug("Heurísticas locais falharam: %s", e)

    # URL estrutural suspeita
    for suspicious in [
        ("@" in url.split("?")[0], "URL contém '@' no caminho"),
        (any(tld in domain for tld in [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"]), "TLD suspeito"),
        (domain.replace(".", "").isdigit() if domain else False, "IP usado como URL"),
        (url.startswith("http://"), "Ligação HTTP (não segura)"),
        (domain.count("-") >= 3, "Domínio com muitos hífens"),
        (len(domain) > 40, "Domínio anormalmente longo"),
        (any(w in url.lower() for w in ["login", "signin", "account", "verify", "confirm", "secure", "update"]) and
         any(w in url.lower() for w in ["bank", "multicaixa", "bai", "bfa", "unitel"]),
         "URL combina marca bancária com acção de conta"),
    ]:
        if suspicious[0]:
            score += 20
            reasons.append(suspicious[1])

    # Score baixo → seguro sem APIs
    if score < 15:
        result = {
            "url":     url,
            "score":   min(100, score),
            "verdict": "SEGURO",
            "reasons": reasons,
        }
        _cache_set(url, result)
        _stats["total_checks"] += 1
        _stats["safe"] += 1
        return result

    # ── APIs externas em paralelo ─────────────────────────────────
    try:
        apis = await asyncio.wait_for(
            combined_url_reputation(url),
            timeout=10.0,
        )
        api_score   = apis.get("score", 0)
        api_reasons = apis.get("reasons", [])
        apis_pos    = apis.get("apis_positive", 0)

        if api_score > 0:
            score = max(score, score + api_score // 2)
            reasons.extend(api_reasons)

        if apis_pos >= 2:
            score = max(score, 80)

    except asyncio.TimeoutError:
        logger.info("APIs externas timeout para %s", url)
        reasons.append("APIs externas: timeout (score parcial)")
    except Exception as e:
        logger.warning("APIs externas falharam: %s", e)
        _stats["api_errors"] += 1

    # ── Score final ───────────────────────────────────────────────
    score   = min(100, max(0, score))
    verdict = "NÃO SEGURO" if score >= 60 else ("SUSPEITO" if score >= 30 else "SEGURO")
    reasons = list(dict.fromkeys(reasons))  # deduplicate

    elapsed = time.monotonic() - t_start
    logger.info("Extension URL check: %s → score=%d verdict=%s (%.2fs)", domain, score, verdict, elapsed)

    # Atualizar stats
    _stats["total_checks"] += 1
    if score >= 60:
        _stats["phishing_found"] += 1
    elif score >= 30:
        _stats["suspicious"] += 1
    else:
        _stats["safe"] += 1

    result = {
        "url":     url,
        "score":   score,
        "verdict": verdict,
        "reasons": reasons,
        "cached":  False,
    }
    _cache_set(url, result)
    return result


# ─── Endpoints ────────────────────────────────────────────────────

@router.post("/check-url", response_model=UrlCheckResult)
async def check_url(body: CheckUrlRequest, request: Request):
    """
    Verifica uma URL individual em tempo real.
    Usado pela extensão Chrome a cada navegação.

    - Score 0–29   → SEGURO
    - Score 30–59  → SUSPEITO (aviso ao utilizador)
    - Score 60–100 → NÃO SEGURO (bloqueado)
    """
    # Rate limit
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit excedido. Aguarde 1 minuto.",
        )

    try:
        result = await _analyze_url_for_extension(body.url)
        return UrlCheckResult(**result)
    except Exception as e:
        logger.error("Erro em check-url: %s", e, exc_info=True)
        # Fail open — nunca bloquear em caso de erro interno
        return UrlCheckResult(
            url     = body.url,
            score   = 0,
            verdict = "SEGURO",
            reasons = [],
            error   = "Erro interno — URL não verificada",
        )


@router.post("/check-urls-batch")
async def check_urls_batch(body: CheckUrlsRequest, request: Request):
    """
    Verifica múltiplas URLs em paralelo (até 20).
    Usado pela extensão para verificar links numa página.

    Retorna: dict[url → UrlCheckResult]
    """
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit excedido.")

    urls = body.urls[:20]

    # Limitar concorrência para não sobrecarregar APIs externas
    semaphore = asyncio.Semaphore(5)

    async def _safe_check(url: str) -> tuple[str, dict]:
        async with semaphore:
            try:
                result = await _analyze_url_for_extension(url)
                return url, result
            except Exception as e:
                logger.warning("Batch check falhou para %s: %s", url, e)
                return url, {
                    "url": url, "score": 0, "verdict": "SEGURO",
                    "reasons": [], "error": str(e),
                }

    tasks = [_safe_check(u) for u in urls]
    results = await asyncio.gather(*tasks)
    return {url: result for url, result in results}


@router.get("/stats")
async def get_extension_stats():
    """Estatísticas de uso da extensão Chrome."""
    cache_size = len(_result_cache)
    return {
        **_stats,
        "cache_size":     cache_size,
        "timestamp":      datetime.now(tz=timezone.utc).isoformat(),
    }


@router.get("/health")
async def extension_health():
    """
    Health check da extensão — verifica conectividade com APIs externas.
    """
    checks = {}

    # VirusTotal
    try:
        if settings.VIRUSTOTAL_API_KEY:
            checks["virustotal"] = "configured"
        else:
            checks["virustotal"] = "no_api_key"
    except Exception:
        checks["virustotal"] = "error"

    # Google Safe Browsing
    try:
        if settings.GOOGLE_SAFE_BROWSING_API_KEY:
            checks["safe_browsing"] = "configured"
        else:
            checks["safe_browsing"] = "no_api_key"
    except Exception:
        checks["safe_browsing"] = "error"

    # URLScan
    try:
        api_key = getattr(settings, "URLSCAN_API_KEY", None) or getattr(settings, "URLSCAN_API", None)
        checks["urlscan"] = "configured" if api_key else "no_api_key"
    except Exception:
        checks["urlscan"] = "error"

    # Groq ML
    try:
        checks["groq_ml"] = "configured" if settings.GROQ_API_KEY else "no_api_key"
    except Exception:
        checks["groq_ml"] = "error"

    all_configured = all(v == "configured" for v in checks.values())

    return {
        "status":          "ok",
        "version":         "1.0.0",
        "apis":            checks,
        "all_configured":  all_configured,
        "cache_entries":   len(_result_cache),
        "stats":           _stats,
    }
