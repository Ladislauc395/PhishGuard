"""
backend/services/orchestrator.py
──────────────────────────────────
Orquestrador v14 — CORRIGIDO

CORRECÇÕES v14:
- orchestrate_url() agora retorna o resultado COMPLETO do url_analyzer
- Cache de 5 minutos para URLs analisadas
- Timeout de 35s para análise completa
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Optional

logger = logging.getLogger(__name__)

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

# Cache
_url_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 300


def _cache_get(url: str) -> Optional[dict]:
    entry = _url_cache.get(url)
    if entry and (time.monotonic() - entry[0]) < _CACHE_TTL:
        return entry[1]
    return None


def _cache_set(url: str, result: dict) -> None:
    _url_cache[url] = (time.monotonic(), result)
    if len(_url_cache) > 1000:
        oldest = sorted(_url_cache.keys(), key=lambda k: _url_cache[k][0])[:200]
        for k in oldest:
            del _url_cache[k]


async def orchestrate_url(url: str) -> dict:
    """Análise de URL - pipeline completo"""
    cached = _cache_get(url)
    if cached:
        logger.info(f"📦 Cache hit: {url[:80]}")
        return {**cached, "cached": True}
    
    try:
        from backend.services.url_analyzer import analyze_url as analyze_url_pipeline
        
        logger.info(f"🔍 Iniciando análise completa: {url[:100]}")
        start_time = time.monotonic()
        
        result = await asyncio.wait_for(
            analyze_url_pipeline(url),
            timeout=35.0
        )
        
        score = result.get("score", 0)
        reasons = result.get("reasons", [])
        classification = result.get("classification", "safe")
        
        # CORRECÇÃO: Mapeamento correto de classificação para veredicto
        if classification == "phishing" or score >= 60:
            verdict = "NÃO SEGURO"
        elif classification == "suspicious" or score >= 30:
            verdict = "SUSPEITO"
        else:
            verdict = "SEGURO"
        
        elapsed = time.monotonic() - start_time
        
        final = {
            "score": score,
            "verdict": verdict,
            "classification": classification,
            "reasons": reasons,
            "url": url,
            "analysis_time_ms": int(elapsed * 1000),
        }
        
        _cache_set(url, final)
        
        logger.info(
            f"✅ Análise concluída: {url[:80]} → score={score}, "
            f"verdict={verdict}, time={elapsed:.2f}s"
        )
        
        return final
    
    except asyncio.TimeoutError:
        logger.warning(f"⏱️ Timeout na análise: {url[:80]}")
        return {
            "score": 50,
            "verdict": "SUSPEITO",
            "classification": "suspicious",
            "reasons": ["analysis_timeout"],
            "url": url,
        }
    
    except Exception as e:
        logger.error(f"❌ Erro na análise: {url[:80]} - {e}", exc_info=True)
        return {
            "score": 0,
            "verdict": "ERRO",
            "classification": "error",
            "reasons": [f"Erro interno: {str(e)[:100]}"],
            "url": url,
        }


async def orchestrate_sms(body: str, phone: str | None = None) -> dict:
    """Análise de SMS"""
    from backend.services.sms_analyzer import analyze_sms
    
    try:
        result = await asyncio.to_thread(analyze_sms, body, phone or "")
        score = result.get("score", 0)
        classification = result.get("classification", "safe")
        
        if classification == "phishing" or score >= 60:
            verdict = "NÃO SEGURO"
        elif classification == "suspicious" or score >= 30:
            verdict = "SUSPEITO"
        else:
            verdict = "SEGURO"
        
        return {
            "score": score,
            "verdict": verdict,
            "classification": classification,
            "reasons": result.get("reasons", []),
            "phone": phone,
        }
    except Exception as e:
        return {"score": 0, "verdict": "ERRO", "reasons": [str(e)], "phone": phone}


async def orchestrate_email(sender: str, headers: str, body: str | None) -> dict:
    """Análise de Email"""
    from backend.services.email_analyzer import analyze_email
    
    try:
        result = await asyncio.to_thread(analyze_email, headers, body or "")
        score = result.get("score", 0)
        classification = result.get("classification", "safe")
        
        if classification == "phishing" or score >= 60:
            verdict = "NÃO SEGURO"
        elif classification == "suspicious" or score >= 30:
            verdict = "SUSPEITO"
        else:
            verdict = "SEGURO"
        
        return {
            "score": score,
            "verdict": verdict,
            "reasons": result.get("reasons", []),
            "auth": result.get("auth", {}),
            "sender": sender,
        }
    except Exception as e:
        return {"score": 0, "verdict": "ERRO", "reasons": [str(e)], "sender": sender}
    