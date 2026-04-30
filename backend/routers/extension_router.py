"""
backend/routers/extension_router.py
──────────────────────────────────────────────────────────────────────────────
Router da extensão Chrome PhishGuard Angola — v4.0

CORRECÇÕES CRÍTICAS v4.0 (em relação à v3.0):
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ BUG 1 (CRÍTICO) — APIs externas nunca corriam quando blacklist dava hit │
  │   ANTES:  `if _HAS_EXTERNAL_APIS and should_check_apis and             │
  │            not blacklisted:`  ← blacklisted=True bloqueava VT/GSB      │
  │   AGORA:  APIs externas correm SEMPRE, sem condição                    │
  │                                                                         │
  │ BUG 2 (CRÍTICO) — Condição `should_check_apis` suprimia APIs           │
  │   ANTES:  Activadas só se score > 5 OU ml >= 40 OU not blacklisted     │
  │           → URL com h=0, ml=0: APIs nunca corriam                      │
  │   AGORA:  Blacklists + APIs correm SEMPRE em paralelo, sem condição    │
  │                                                                         │
  │ BUG 3 — Score final diluía detecções individuais fortes                │
  │   ANTES:  Média ponderada podia dar 20 mesmo com api_score=90          │
  │   AGORA:  final_score = max(média_ponderada, TODAS_as_fontes)          │
  │                                                                         │
  │ BUG 4 — Blacklists e APIs corriam sequencialmente                      │
  │   AGORA:  asyncio.gather → Blacklists + APIs + ML em PARALELO          │
  │           Latência: de ~30s sequencial para ~15s paralelo              │
  └─────────────────────────────────────────────────────────────────────────┘

PIPELINE DE ANÁLISE v4.0 — análise híbrida verdadeira:
  Fase A (síncrono, <1 ms):  Heurísticas locais (estrutura da URL)
  Fase B (paralelo ~1-5s):   evaluate_domain (typosquatting) + ML classifier
  Fase C (paralelo ~5-18s):  PhishTank/OpenPhish + VirusTotal/GSB/URLScan

SCORE FINAL (lógica de máximo garantido):
  • final_score = max(média_ponderada, h_score, ml_score, bl_score, api_score)
  • Nenhuma fonte forte é diluída pelas restantes.
  • Blacklist ≥ 90 → score final = max(bl_score, api_score).
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

# ─── Imports defensivos ───────────────────────────────────────────

try:
    from backend.services.external_apis import (
        combined_url_reputation,
        phishing_blacklist_check,
    )
    _HAS_EXTERNAL_APIS = True
    _HAS_BLACKLIST     = True
    logger.info("external_apis carregado ✓")
except ImportError as _e:
    _HAS_EXTERNAL_APIS = False
    _HAS_BLACKLIST     = False
    logger.warning("external_apis não disponível: %s", _e)

try:
    from backend.services.ml_url_classifier import analyze_url_with_ml
    _HAS_ML = True
    logger.info("ml_url_classifier carregado ✓")
except ImportError as _e:
    _HAS_ML = False
    logger.warning("ml_url_classifier não disponível: %s", _e)

try:
    from backend.services.heuristics import evaluate_domain
    _HAS_HEURISTICS = True
except ImportError:
    _HAS_HEURISTICS = False

try:
    from backend.core.config import settings as _cfg
    _HAS_SETTINGS = True
except ImportError:
    _cfg          = None
    _HAS_SETTINGS = False

# ─── Configuração ─────────────────────────────────────────────────

_BACKEND_PUBLIC_URL = "http://10.249.221.68:8000"
_CHROME_STORE_ID    = ""
_CHROME_STORE_URL   = (
    f"https://chrome.google.com/webstore/detail/{_CHROME_STORE_ID}"
    if _CHROME_STORE_ID else ""
)

# ─── Rate limiting ────────────────────────────────────────────────

_rate_limit: dict[str, list[float]] = {}
_RATE_WINDOW = 60.0
_RATE_MAX    = 60


def _check_rate_limit(ip: str) -> bool:
    now  = time.monotonic()
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
    k     = _cache_key(url)
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
    "total_checks":   0,
    "phishing_found": 0,
    "suspicious":     0,
    "safe":           0,
    "cache_hits":     0,
    "api_errors":     0,
    "blacklist_hits": 0,
    "ml_detections":  0,
    "started_at":     datetime.now(tz=timezone.utc).isoformat(),
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


class UrlCheckResult(BaseModel):
    url:     str
    score:   int
    verdict: str
    reasons: List[str]
    cached:  bool = False
    error:   Optional[str] = None


# ─── Heurísticas locais ───────────────────────────────────────────

_SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".click", ".download", ".loan", ".work", ".win",
    ".cam", ".icu", ".surf", ".monster", ".live", ".online",
    ".site", ".website", ".press", ".space", ".fun", ".host",
    ".shop", ".store", ".vip", ".bid", ".stream",
}

_BANK_KEYWORDS = {
    "multicaixa", "bai", "bfa", "bca", "unitel", "bna",
    "angola", "kwanza", "atlantico", "standard", "emis",
}
_ACTION_KEYWORDS = {
    "login", "signin", "account", "verify", "confirm",
    "secure", "update", "password", "reset", "wallet",
    "banking", "payment", "credential", "validate",
}


def _local_heuristics(url: str) -> tuple[int, list[str]]:
    score   = 0
    reasons: list[str] = []
    try:
        parsed = urlparse(url)
        host   = (parsed.hostname or "").lower()
        full   = url.lower()
    except Exception:
        return 0, []

    if url.startswith("http://"):
        score += 15
        reasons.append("Ligação HTTP não encriptada")

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 40
        reasons.append("Endereço IP usado directamente como URL")

    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 25
            reasons.append(f"TLD suspeito: {tld}")
            break

    if "@" in (parsed.path or "") or "@" in (parsed.netloc or ""):
        score += 35
        reasons.append("Símbolo '@' detectado na URL")

    if host.count("-") >= 3:
        score += 15
        reasons.append(f"Domínio com {host.count('-')} hífens (suspeito)")

    if len(host) > 45:
        score += 15
        reasons.append(f"Domínio anormalmente longo ({len(host)} caracteres)")

    if any(k in full for k in _BANK_KEYWORDS) and any(k in full for k in _ACTION_KEYWORDS):
        score += 30
        reasons.append("URL combina marca bancária angolana com acção de autenticação")

    parts = host.split(".")
    if len(parts) > 4:
        score += 10
        reasons.append(f"Muitos subdomínios ({len(parts) - 2} níveis)")

    for h in {"ngrok.io", "ngrok-free.app", "netlify.app", "github.io",
               "vercel.app", "pages.dev", "glitch.me", "replit.co",
               "000webhost.com", "weebly.com", "wixsite.com"}:
        if h in host:
            score += 30
            reasons.append(f"Hosting gratuito suspeito: {h}")
            break

    return min(100, score), reasons


# ─── Wrappers seguros (nunca lançam excepção) ─────────────────────
# Cada wrapper captura TUDO e devolve um dict neutro em caso de falha.
# Garante que uma API lenta/offline nunca cancela as restantes.

async def _safe_ml(url: str) -> dict:
    """ML URL Classifier (RandomForest + XGBoost) — sempre tentado."""
    if not _HAS_ML:
        return {"ml_score": 0, "reasons": [], "method": "unavailable"}
    try:
        return await asyncio.wait_for(analyze_url_with_ml(url), timeout=6.0)
    except asyncio.TimeoutError:
        logger.debug("ML timeout: %s", url[:60])
        return {"ml_score": 0, "reasons": [], "method": "timeout"}
    except Exception as exc:
        logger.debug("ML erro: %s", exc)
        return {"ml_score": 0, "reasons": [], "method": "error"}


async def _safe_blacklists(url: str) -> dict:
    """PhishTank + OpenPhish — SEMPRE executados, sem condição."""
    if not _HAS_BLACKLIST:
        return {"score": 0, "reasons": [], "blacklisted": False,
                "phishtank": {}, "openphish": {}, "source": "unavailable"}
    try:
        result = await asyncio.wait_for(phishing_blacklist_check(url), timeout=14.0)
        return result
    except asyncio.TimeoutError:
        logger.warning("Blacklists timeout: %s", url[:60])
        return {"score": 0, "reasons": ["Blacklists: timeout — resultado parcial"],
                "blacklisted": False, "phishtank": {}, "openphish": {}, "source": "timeout"}
    except Exception as exc:
        logger.warning("Blacklists erro: %s", exc)
        _stats["api_errors"] += 1
        return {"score": 0, "reasons": [], "blacklisted": False,
                "phishtank": {}, "openphish": {}, "source": "error"}


async def _safe_external_apis(url: str) -> dict:
    """
    VirusTotal + Google Safe Browsing + URLScan — SEMPRE executados, sem condição.

    combined_url_reputation() corre PhishTank + OpenPhish + VT + GSB + URLScan
    internamente em paralelo. Usamos o seu resultado para VT/GSB/URLScan;
    os scores de PhishTank/OpenPhish vêm de _safe_blacklists() separado para
    termos os dois scores independentes no cálculo final.
    """
    if not _HAS_EXTERNAL_APIS:
        return {"score": 0, "reasons": [], "apis_positive": 0,
                "malicious": False, "blacklisted": False, "source": "unavailable"}
    try:
        result = await asyncio.wait_for(combined_url_reputation(url), timeout=20.0)
        return result
    except asyncio.TimeoutError:
        logger.info("APIs externas timeout: %s", url[:60])
        return {"score": 0, "reasons": ["APIs externas (VT/GSB/URLScan): timeout"],
                "apis_positive": 0, "malicious": False, "blacklisted": False, "source": "timeout"}
    except Exception as exc:
        logger.warning("APIs externas erro: %s", exc)
        _stats["api_errors"] += 1
        return {"score": 0, "reasons": [], "apis_positive": 0,
                "malicious": False, "blacklisted": False, "source": "error"}


async def _safe_heuristics_advanced(url: str) -> tuple[int, list[str]]:
    """evaluate_domain — typosquatting e brand spoofing avançado."""
    if not _HAS_HEURISTICS:
        return 0, []
    try:
        domain_result = await asyncio.wait_for(evaluate_domain(url, []), timeout=3.0)
        adv_score   = 0
        adv_reasons: list[str] = []
        if getattr(domain_result, "typosquatting_detected", False):
            adv_score += 50
            brand = getattr(domain_result, "suspected_brand", "desconhecida")
            adv_reasons.append(f"Typosquatting: domínio imita '{brand}'")
        if getattr(domain_result, "official_match", True) is False:
            brand = getattr(domain_result, "suspected_brand", None)
            if brand:
                adv_score += 20
                adv_reasons.append(f"Marca '{brand}' em domínio não oficial")
        return adv_score, adv_reasons
    except Exception as exc:
        logger.debug("evaluate_domain falhou: %s", exc)
        return 0, []


# ─── Pipeline principal de análise v4.0 ──────────────────────────

async def _analyze_url(url: str) -> dict:
    """
    Pipeline híbrido v4.0 — TODAS as fontes sempre activas.

    Fase A (síncrono, <1 ms):
      • Heurísticas locais (estrutura da URL)

    Fase B (paralelo, ~1-5s):
      • evaluate_domain (typosquatting)
      • ML URL Classifier (RandomForest + XGBoost)

    Fase C (paralelo, ~5-20s — a fase mais importante):
      • _safe_blacklists()     → PhishTank + OpenPhish (SEMPRE)
      • _safe_external_apis()  → VT + GSB + URLScan    (SEMPRE)

    CORRECÇÃO PRINCIPAL: as Fases B e C correm SEMPRE para QUALQUER URL,
    independentemente do score heurístico. Não há condições de activação.

    Score final:
      • final_score = max(média_ponderada, h, ml, bl, api)
      • Uma fonte a detectar claramente nunca é diluída pelas restantes.
    """
    # ── 1. Cache ─────────────────────────────────────────────────
    cached = _cache_get(url)
    if cached:
        _stats["cache_hits"] += 1
        return {**cached, "cached": True}

    t0 = time.monotonic()

    # ── Fase A: heurísticas locais (síncrono, <1 ms) ─────────────
    h_score, h_reasons = _local_heuristics(url)

    # ── Fase B: heurísticas avançadas + ML em paralelo ────────────
    (adv_score, adv_reasons), ml_result = await asyncio.gather(
        _safe_heuristics_advanced(url),
        _safe_ml(url),
    )

    ml_score   = ml_result.get("ml_score", 0)
    ml_reasons = ml_result.get("reasons", [])

    # Combinar score heurístico com avançado
    h_score   = min(100, h_score + adv_score)
    h_reasons = h_reasons + adv_reasons

    # ── Fase C: Blacklists + APIs externas em PARALELO ───────────
    # CORRECÇÃO PRINCIPAL:
    #   • Sem `should_check_apis` condicional
    #   • Sem `not blacklisted` a bloquear as APIs externas
    #   • Ambas correm SEMPRE, seja qual for o score das fases anteriores
    bl_result, api_result = await asyncio.gather(
        _safe_blacklists(url),
        _safe_external_apis(url),
    )

    bl_score    = bl_result.get("score", 0)
    bl_reasons  = bl_result.get("reasons", [])
    blacklisted = bl_result.get("blacklisted", False)

    api_score   = api_result.get("score", 0)
    api_reasons = api_result.get("reasons", [])

    # Actualizar estatísticas
    if blacklisted:
        _stats["blacklist_hits"] += 1
        logger.info("BLACKLIST HIT: %s → bl_score=%d api_score=%d",
                    url[:60], bl_score, api_score)

    if ml_score >= 60:
        _stats["ml_detections"] += 1

    # ── Calcular score final ──────────────────────────────────────
    # Regra: nenhuma fonte forte é diluída pela média das outras.

    if blacklisted and bl_score >= 90:
        # Blacklist confirmada → score final é o máximo (API pode ser ainda maior)
        final_score = int(max(bl_score, api_score))
    else:
        # Média ponderada híbrida:
        #   heurísticas   25%  (estruturais, rápidas)
        #   ML            30%  (comportamental, local)
        #   blacklists    20%  (PhishTank + OpenPhish)
        #   APIs externas 25%  (VT + GSB + URLScan)
        weighted = (
            h_score   * 0.25 +
            ml_score  * 0.30 +
            bl_score  * 0.20 +
            api_score * 0.25
        )
        # Garantir que nenhuma fonte forte é ignorada
        # (ml_score só entra no max se >= 60, para não inflar scores marginais)
        final_score = int(max(
            weighted,
            h_score,
            ml_score if ml_score >= 60 else 0,
            bl_score,
            api_score,
        ))

    final_score = min(100, max(0, final_score))

    # ── Agregar razões (sem duplicados, prioridade: bl > api > ml > h) ──
    seen: set[str] = set()
    all_reasons: list[str] = []
    for r in (*bl_reasons, *api_reasons, *ml_reasons, *h_reasons):
        if r not in seen:
            seen.add(r)
            all_reasons.append(r)

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
        "Check v4: %s → %d (%s) | h=%d ml=%d bl=%d api=%d | %.2fs",
        host_label, final_score, verdict,
        h_score, ml_score, bl_score, api_score, elapsed,
    )

    _stats["total_checks"] += 1
    if final_score >= 60:
        _stats["phishing_found"] += 1
    elif final_score >= 30:
        _stats["suspicious"] += 1
    else:
        _stats["safe"] += 1

    result = {
        "url":         url,
        "score":       final_score,
        "verdict":     verdict,
        "reasons":     all_reasons,
        "cached":      False,
        "blacklisted": blacklisted,
        "ml_score":    ml_score,
        "details": {
            "heuristic_score":  h_score,
            "ml_score":         ml_score,
            "blacklist_score":  bl_score,
            "api_score":        api_score,
            "elapsed_seconds":  round(elapsed, 2),
            "pipeline_version": "4.0",
        },
    }
    _cache_set(url, result)
    return result


# ─── CORS helpers ─────────────────────────────────────────────────

def _cors() -> dict:
    return {
        "Access-Control-Allow-Origin":  "*",
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
    """
    Verificar uma URL individual — pipeline híbrido v4.0.

    Fontes activas SEMPRE (em paralelo):
      Heurísticas + ML + PhishTank + OpenPhish + VirusTotal + GSB + URLScan
    Score 0–29 → SEGURO | 30–59 → SUSPEITO | 60+ → NÃO SEGURO
    """
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit excedido. Aguarde 1 minuto.")

    try:
        result = await _analyze_url(body.url)
        return JSONResponse(content=result, headers=_cors())
    except Exception as exc:
        logger.error("Erro em /check-url: %s", exc, exc_info=True)
        return JSONResponse(
            content={
                "url": body.url, "score": 0,
                "verdict": "ERRO",
                "reasons": ["Erro interno — URL não verificada"],
                "error": str(exc), "cached": False,
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
            return url, await _analyze_url(url)
        except Exception as exc:
            logger.warning("Batch falhou para %s: %s", url, exc)
            return url, {
                "url": url, "score": 0, "verdict": "SEGURO",
                "reasons": [], "error": str(exc), "cached": False,
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
            "timestamp":  datetime.now(tz=timezone.utc).isoformat(),
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
        "virustotal":    _key_ok("VIRUSTOTAL_API_KEY"),
        "safe_browsing": _key_ok("GOOGLE_SAFE_BROWSING_API_KEY"),
        "urlscan":       _key_ok("URLSCAN_API_KEY", "URLSCAN_API"),
        "abuseipdb":     _key_ok("ABUSEIPDB_API_KEY"),
        "phishtank":     "configured",           # gratuito, sempre activo
        "openphish":     "configured",           # gratuito, sempre activo
        "ml_classifier": "configured" if _HAS_ML else "not_installed",
    }
    apis_configured = sum(1 for v in apis_status.values() if v == "configured")

    return JSONResponse(
        content={
            "backend_url":            _BACKEND_PUBLIC_URL,
            "check_url_endpoint":     f"{_BACKEND_PUBLIC_URL}/extension/check-url",
            "chrome_store_url":       _CHROME_STORE_URL,
            "chrome_store_available": bool(_CHROME_STORE_ID),
            "backend_online":         True,
            "apis_configured":        apis_configured,
            "apis_total":             len(apis_status),
            "apis_status":            apis_status,
            "total_checks":           _stats["total_checks"],
            "phishing_blocked":       _stats["phishing_found"],
            "blacklist_hits":         _stats["blacklist_hits"],
            "ml_detections":          _stats["ml_detections"],
            "cache_entries":          len(_result_cache),
            "pipeline_version":       "4.0",
            "timestamp":              datetime.now(tz=timezone.utc).isoformat(),
        },
        headers=_cors(),
    )


@router.get("/health")
async def extension_health():
    """Health check rápido — não faz chamadas de rede."""
    def _key_ok(*attrs: str) -> str:
        if not _HAS_SETTINGS or _cfg is None:
            return "settings_unavailable"
        for attr in attrs:
            if getattr(_cfg, attr, None):
                return "configured"
        return "no_api_key"

    apis = {
        "virustotal":    _key_ok("VIRUSTOTAL_API_KEY"),
        "safe_browsing": _key_ok("GOOGLE_SAFE_BROWSING_API_KEY"),
        "urlscan":       _key_ok("URLSCAN_API_KEY", "URLSCAN_API"),
        "abuseipdb":     _key_ok("ABUSEIPDB_API_KEY"),
        "phishtank":     "configured",
        "openphish":     "configured",
        "ml_classifier": "configured" if _HAS_ML else "not_installed",
    }

    return JSONResponse(
        content={
            "status":         "ok",
            "version":        "4.0.0",
            "pipeline":       "heuristics+ml ∥ blacklists+external_apis",
            "apis":           apis,
            "all_configured": all(v == "configured" for v in apis.values()),
            "has_ml":         _HAS_ML,
            "has_blacklist":  _HAS_BLACKLIST,
            "has_external":   _HAS_EXTERNAL_APIS,
            "cache_entries":  len(_result_cache),
            "heuristics_ok":  True,
            "backend_url":    _BACKEND_PUBLIC_URL,
            "stats":          _stats,
        },
        headers=_cors(),
    )