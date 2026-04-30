"""
backend/services/external_apis.py
──────────────────────────────────────────────────────────────────────────────
Integrações externas v14 — PhishGuard Angola

CORRECÇÕES v14:
- VirusTotal: polling aumentado para 5 tentativas × 5s (25s total) para garantir
  que URLs recentemente submetidas têm tempo de serem analisadas
- Logs mais detalhados para debug
- Timeout aumentado para 15s em cada chamada
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from backend.core.config import settings

logger = logging.getLogger(__name__)

# ─── Cache simples com TTL ─────────────────────────────────────────
_TTL = 600  # 10 minutos para APIs de reputação
_TTL_BLACKLIST = 21600  # 6 horas para feed

_vt_cache: dict[str, tuple[float, dict]] = {}
_gsb_cache: dict[str, tuple[float, dict]] = {}
_urlscan_cache: dict[str, tuple[float, dict]] = {}
_combined_cache: dict[str, tuple[float, dict]] = {}
_phishtank_cache: dict[str, tuple[float, dict]] = {}
_openphish_cache: dict[str, tuple[float, dict]] = {}

# Cache do feed OpenPhish em memória (lista de URLs)
_openphish_feed: list[str] = []
_openphish_loaded: float = 0.0

# Cache do feed URLhaus
_urlhaus_feed_urls: set[str] = set()
_urlhaus_feed_domains: set[str] = set()
_urlhaus_feed_loaded: float = 0.0

_TTL_URLHAUS = 3600  # 1 hora

_URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"
_URLHAUS_FEED_URL_ONLINE = "https://urlhaus.abuse.ch/downloads/json_online/"


def _get(cache: dict, key: str, ttl: int = _TTL) -> Optional[dict]:
    entry = cache.get(key)
    if entry and (time.monotonic() - entry[0]) < ttl:
        return entry[1]
    return None


def _set(cache: dict, key: str, value: dict) -> None:
    cache[key] = (time.monotonic(), value)


def _normalize_url(url: str) -> str:
    url = url.strip().lower()
    if url.endswith("/"):
        url = url.rstrip("/")
    return url


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


# ─── URLhaus Feed (substituto do PhishTank offline) ────────────────

async def _load_urlhaus_feed() -> bool:
    global _urlhaus_feed_urls, _urlhaus_feed_domains, _urlhaus_feed_loaded

    now = time.monotonic()
    if _urlhaus_feed_urls and (now - _urlhaus_feed_loaded) < _TTL_URLHAUS:
        return True

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            feed_urls_to_try = [_URLHAUS_FEED_URL_ONLINE, _URLHAUS_FEED_URL]
            r = None
            for feed_url in feed_urls_to_try:
                try:
                    r = await c.get(
                        feed_url,
                        headers={"User-Agent": "phishguard-angola/2.0"},
                        follow_redirects=True,
                    )
                    if r.status_code == 200:
                        break
                except Exception:
                    continue

            if r is None or r.status_code != 200:
                logger.warning("URLhaus feed: todos os feeds falharam")
                return False

            data = r.json()
            entries = []
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, list):
                        entries.extend(v)
                    elif isinstance(v, dict):
                        entries.append(v)

            urls: set[str] = set()
            domains: set[str] = set()

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                status = entry.get("url_status") or entry.get("status") or "online"
                if status == "offline":
                    continue
                raw = entry.get("url") or entry.get("url_url") or entry.get("link") or ""
                if not raw and isinstance(entry.get("url"), dict):
                    raw = entry["url"].get("url", "") or ""

                if raw and isinstance(raw, str) and raw.startswith("http"):
                    norm = _normalize_url(raw)
                    urls.add(norm)
                    dom = _extract_domain(raw)
                    if dom:
                        domains.add(dom)

            _urlhaus_feed_urls = urls
            _urlhaus_feed_domains = domains
            _urlhaus_feed_loaded = now

            if len(urls) == 0:
                logger.warning("URLhaus feed: 0 URLs extraídas")
            else:
                logger.info("URLhaus feed carregado: %d URLs activas, %d domínios",
                            len(urls), len(domains))
            return len(urls) > 0

    except Exception as e:
        logger.warning("URLhaus feed falhou: %s", e)
        return False


async def check_urlhaus_feed(url: str) -> dict:
    if not _urlhaus_feed_urls:
        await _load_urlhaus_feed()

    if not _urlhaus_feed_urls:
        return {"in_database": False, "verified": False, "valid": False,
                "source": "urlhaus_feed", "error": "feed_unavailable"}

    norm_url = _normalize_url(url)
    url_domain = _extract_domain(url)

    exact_match = norm_url in _urlhaus_feed_urls
    domain_match = bool(url_domain) and url_domain in _urlhaus_feed_domains

    found = exact_match or domain_match
    result = {
        "in_database": found,
        "verified": found,
        "valid": found,
        "exact_match": exact_match,
        "domain_match": domain_match,
        "source": "urlhaus_feed",
    }

    if found:
        logger.info("URLhaus FEED HIT: %s (exact=%s domain=%s)",
                    url[:60], exact_match, domain_match)
    return result


# ─── OpenPhish ────────────────────────────────────────────────────

async def _load_openphish_feed() -> list[str]:
    global _openphish_feed, _openphish_loaded

    now = time.monotonic()
    if _openphish_feed and (now - _openphish_loaded) < _TTL_BLACKLIST:
        return _openphish_feed

    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                "https://openphish.com/feed.txt",
                headers={"User-Agent": "phishguard-angola/2.0"},
                follow_redirects=True,
            )
            if r.status_code == 200:
                lines = [
                    _normalize_url(line.strip())
                    for line in r.text.splitlines()
                    if line.strip().startswith("http")
                ]
                _openphish_feed = lines
                _openphish_loaded = now
                logger.info("OpenPhish feed carregado: %d URLs", len(lines))
                return lines
    except Exception as e:
        logger.warning("OpenPhish feed falhou: %s", e)

    return _openphish_feed


async def check_openphish(url: str) -> dict:
    cached = _get(_openphish_cache, url, ttl=_TTL_BLACKLIST)
    if cached:
        return {**cached, "cached": True}

    feed = await _load_openphish_feed()
    norm_url = _normalize_url(url)
    url_domain = _extract_domain(url)

    exact_match = norm_url in feed
    domain_match = False
    if url_domain and not exact_match:
        domain_match = any(_extract_domain(feed_url) == url_domain for feed_url in feed)

    result = {
        "found": exact_match or domain_match,
        "exact_match": exact_match,
        "domain_match": domain_match,
        "source": "openphish",
    }
    _set(_openphish_cache, url, result)

    if result["found"]:
        logger.info("OpenPhish HIT: %s (exact=%s domain=%s)",
                    url[:60], exact_match, domain_match)

    return result


# ─── PhishTank API (online) ──────────────────────────────────────

async def check_phishtank(url: str) -> dict:
    cached = _get(_phishtank_cache, url, ttl=_TTL_BLACKLIST)
    if cached:
        return {**cached, "cached": True}

    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json"},
                headers={"User-Agent": "phishguard-angola/2.0"},
            )

            if r.status_code in (429, 509):
                logger.warning("PhishTank rate limit, usando feed URLhaus")
                return await check_urlhaus_feed(url)

            if r.status_code != 200:
                return await check_urlhaus_feed(url)

            data = r.json()
            results = data.get("results", {})

            result = {
                "in_database": results.get("in_database", False),
                "verified": results.get("verified", False),
                "valid": results.get("valid", False),
                "phish_id": str(results.get("phish_id", "")),
                "source": "phishtank",
            }
            _set(_phishtank_cache, url, result)
            return result

    except Exception as e:
        logger.warning("PhishTank falhou: %s", e)
        return await check_urlhaus_feed(url)


# ─── Blacklist agregada ─────────────────────────────────────────

async def phishing_blacklist_check(url: str) -> dict:
    pt_task, op_task = await asyncio.gather(
        check_phishtank(url),
        check_openphish(url),
        return_exceptions=True,
    )

    if isinstance(pt_task, Exception):
        pt_task = {"in_database": False, "verified": False}
    if isinstance(op_task, Exception):
        op_task = {"found": False}

    blacklisted = False
    score = 0
    reasons: list[str] = []

    # PhishTank/URLhaus
    if pt_task.get("verified") and pt_task.get("valid"):
        blacklisted = True
        score = max(score, 98)
        reasons.append("URLhaus/PhishTank: URL confirmada como phishing activo")
    elif pt_task.get("verified"):
        blacklisted = True
        score = max(score, 92)
        reasons.append("Blacklist: URL verificada como phishing")
    elif pt_task.get("in_database"):
        score = max(score, 75)
        reasons.append("Blacklist: URL encontrada na base de dados")

    # OpenPhish
    if op_task.get("found"):
        blacklisted = True
        if op_task.get("exact_match"):
            score = max(score, 96)
            reasons.append("OpenPhish: URL exacta no feed de phishing activo")
        elif op_task.get("domain_match"):
            score = max(score, 88)
            reasons.append("OpenPhish: domínio no feed de phishing")

    return {
        "blacklisted": blacklisted,
        "score": min(100, score),
        "reasons": reasons,
        "phishtank": pt_task,
        "openphish": op_task,
    }


# ─── VirusTotal (CORRIGIDO v14) ───────────────────────────────────

async def check_virustotal(url: str) -> dict:
    cached = _get(_vt_cache, url)
    if cached:
        return {**cached, "cached": True}

    if not settings.VIRUSTOTAL_API_KEY:
        return {"malicious": 0, "suspicious": 0, "found": False, "error": "no_api_key"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=15) as c:
            # Tentar obter análise existente
            r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

            if r.status_code == 404:
                logger.info("VT: URL nova, submetendo: %s", url[:60])
                submit = await c.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                )
                if submit.status_code not in (200, 201, 202):
                    return {"malicious": 0, "suspicious": 0, "found": False, "status": "submit_failed"}

                # Polling: 5 tentativas × 5s = 25s total (aumentado v14)
                for attempt in range(5):
                    await asyncio.sleep(5)
                    try:
                        poll = await c.get(
                            f"https://www.virustotal.com/api/v3/urls/{url_id}",
                            headers=headers,
                            timeout=10,
                        )
                        if poll.status_code == 200:
                            stats = (poll.json()
                                     .get("data", {})
                                     .get("attributes", {})
                                     .get("last_analysis_stats", {}))
                            result = {
                                "malicious": stats.get("malicious", 0),
                                "suspicious": stats.get("suspicious", 0),
                                "found": True,
                                "status": "analysed",
                            }
                            _set(_vt_cache, url, result)
                            logger.info("VT analysis completed: %d malicious, %d suspicious",
                                        result["malicious"], result["suspicious"])
                            return result
                        logger.info("VT polling %d/5 - aguardando análise", attempt + 1)
                    except Exception as e:
                        logger.debug(f"VT poll attempt {attempt + 1} failed: {e}")

                result = {"malicious": 0, "suspicious": 0, "found": False, "status": "pending"}
                _set(_vt_cache, url, result)
                return result

            if r.status_code == 429:
                return {"malicious": 0, "suspicious": 0, "found": False, "error": "rate_limit"}

            r.raise_for_status()
            stats = (r.json()
                     .get("data", {})
                     .get("attributes", {})
                     .get("last_analysis_stats", {}))
            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "found": True,
            }
            _set(_vt_cache, url, result)
            logger.debug("VT cache hit: %d malicious, %d suspicious",
                         result["malicious"], result["suspicious"])
            return result

    except httpx.TimeoutException:
        logger.warning("VT timeout para: %s", url[:60])
        return {"malicious": 0, "suspicious": 0, "found": False, "error": "timeout"}
    except Exception as e:
        logger.warning("VT falhou: %s", e)
        return {"malicious": 0, "suspicious": 0, "found": False, "error": str(e)}


# ─── AbuseIPDB ────────────────────────────────────────────────────

async def check_abuseipdb(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {"abuse_score": 0, "error": "no_api_key"}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            r.raise_for_status()
            d = r.json().get("data", {})
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode"),
            }
    except Exception as e:
        logger.error("AbuseIPDB falhou: %s", e)
        return {"abuse_score": 0, "error": str(e)}


# ─── Google Safe Browsing ─────────────────────────────────────────

async def check_safe_browsing(url: str) -> dict:
    cached = _get(_gsb_cache, url)
    if cached:
        return {**cached, "cached": True}

    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return {"threat": False, "error": "no_api_key"}

    payload = {
        "client": {"clientId": "phishguard-angola", "clientVersion": "2.1"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    last_err = ""
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                    f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
                    json=payload,
                )
                r.raise_for_status()
                matches = r.json().get("matches", [])
                result = {
                    "threat": bool(matches),
                    "types": [m.get("threatType") for m in matches],
                }
                _set(_gsb_cache, url, result)
                if result["threat"]:
                    logger.info("GSB threat detected for %s", url[:60])
                return result
        except httpx.TimeoutException:
            last_err = "timeout"
            await asyncio.sleep(1)
        except Exception as e:
            last_err = str(e)
            break

    result = {"threat": False, "error": last_err}
    _set(_gsb_cache, url, result)
    return result


# ─── URLScan ──────────────────────────────────────────────────────

async def check_urlscan_existing(url: str) -> dict:
    cached = _get(_urlscan_cache, f"existing:{url}")
    if cached:
        return {**cached, "cached": True}

    try:
        norm = _normalize_url(url)
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f'page.url:"{norm}"', "size": 1},
            )
            if r.status_code == 200:
                results = r.json().get("results", [])
                if results:
                    latest = results[0]
                    verdicts = latest.get("verdicts", {})
                    overall = verdicts.get("overall", {})
                    result = {
                        "found": True,
                        "malicious": overall.get("malicious", False),
                        "score": overall.get("score", 0),
                        "uuid": latest.get("_id", ""),
                    }
                    _set(_urlscan_cache, f"existing:{url}", result)
                    return result
            return {"found": False}
    except Exception as e:
        logger.warning("URLScan search falhou: %s", e)
        return {"found": False, "error": str(e)}


# ─── Combined Reputation ─────────────────────────────────────────

async def combined_url_reputation(url: str) -> dict:
    cached = _get(_combined_cache, url)
    if cached:
        return {**cached, "cached": True}

    bl_task = phishing_blacklist_check(url)
    vt_task = check_virustotal(url)
    gsb_task = check_safe_browsing(url)
    urlscan_task = check_urlscan_existing(url)

    bl, vt, gsb, urlscan = await asyncio.gather(
        bl_task, vt_task, gsb_task, urlscan_task,
        return_exceptions=True,
    )

    if isinstance(bl, Exception):
        bl = {"blacklisted": False, "score": 0, "reasons": []}
    if isinstance(vt, Exception):
        vt = {"malicious": 0, "suspicious": 0}
    if isinstance(gsb, Exception):
        gsb = {"threat": False}
    if isinstance(urlscan, Exception):
        urlscan = {"found": False}

    score = 0
    reasons: list[str] = []
    apis_positive = 0

    # Blacklist
    if bl.get("blacklisted"):
        score = max(score, bl.get("score", 90))
        apis_positive += 1
        reasons.extend(bl.get("reasons", []))

    # GSB
    if gsb.get("threat"):
        score = max(score, 85)
        reasons.append("Google Safe Browsing: ameaça detectada")
        apis_positive += 1

    # VirusTotal
    vt_mal = vt.get("malicious", 0)
    vt_sus = vt.get("suspicious", 0)
    if vt_mal >= 3:
        score = max(score, 75)
        reasons.append(f"VirusTotal: {vt_mal} motores maliciosos")
        apis_positive += 1
    elif vt_mal >= 2:
        score = max(score, 60)
        reasons.append(f"VirusTotal: {vt_mal} motores maliciosos")
        apis_positive += 1
    elif vt_mal == 1:
        score = max(score, 40)
        reasons.append("VirusTotal: 1 motor malicioso (suspeito)")

    # URLScan
    if urlscan.get("malicious"):
        score = max(score, 60)
        reasons.append("URLScan.io: URL maliciosa")
        apis_positive += 1

    result = {
        "score": min(100, score),
        "malicious": score >= 60,
        "apis_positive": apis_positive,
        "blacklisted": bl.get("blacklisted", False),
        "vt": vt,
        "gsb": gsb,
        "urlscan": urlscan,
        "reasons": reasons,
    }
    _set(_combined_cache, url, result)
    return result