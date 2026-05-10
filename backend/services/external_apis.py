"""
backend/services/external_apis.py
──────────────────────────────────
Integrações externas v18 — PhishGuard Angola

CORRECÇÕES v18:
- PhishTank: feed local carregado em background para resposta instantânea.
- VirusTotal: apenas GET (sem submissão).
- SSL check corrigido (datas com timezone UTC).
- Google Safe Browsing, AbuseIPDB, URLScan, DNSBL com timeouts ajustados.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import whois   # pip install python-whois

from backend.core.config import settings

logger = logging.getLogger(__name__)

# ─── Cache ────────────────────────────────────────────────────────
_TTL = 600
_TTL_BLACKLIST = 21600

_cache: dict[str, tuple[float, dict]] = {}

def _get_cache(key: str, ttl: int = _TTL) -> Optional[dict]:
    entry = _cache.get(key)
    if entry and (time.monotonic() - entry[0]) < ttl:
        return entry[1]
    return None

def _set_cache(key: str, value: dict) -> None:
    _cache[key] = (time.monotonic(), value)
    if len(_cache) > 5000:
        oldest = sorted(_cache.keys(), key=lambda k: _cache[k][0])[:1000]
        for k in oldest:
            del _cache[k]


# ═══════════════════════════════════════════════════════════════════
# Feed local do PhishTank (carregado em background)
# ═══════════════════════════════════════════════════════════════════

_PHISHTANK_FEED_DOMAINS: set[str] = set()
_PHISHTANK_FEED_READY = False

async def _load_phishtank_feed_async():
    global _PHISHTANK_FEED_DOMAINS, _PHISHTANK_FEED_READY
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(
                "https://data.phishtank.com/data/online-valid.json",
                headers={"User-Agent": "phishguard/2.0"},
                follow_redirects=True,
            )
            if r.status_code == 200:
                data = r.json()
                domains = set()
                for entry in data:
                    url = entry.get("url", "")
                    if url:
                        try:
                            d = urlparse(url).hostname
                            if d:
                                domains.add(d.lower())
                        except Exception:
                            pass
                _PHISHTANK_FEED_DOMAINS = domains
                logger.info("✅ Feed PhishTank carregado: %d domínios", len(domains))
    except Exception as e:
        logger.warning("🔥 Feed PhishTank offline: %s", e)
    finally:
        _PHISHTANK_FEED_READY = True

def _start_feed_loader():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_load_phishtank_feed_async())
    except Exception:
        pass

threading.Thread(target=_start_feed_loader, daemon=True).start()


# ═══════════════════════════════════════════════════════════════════
# PhishTank (feed local + API)
# ═══════════════════════════════════════════════════════════════════

PHISHTANK_API_KEY = "3b9c8e5a1d2f4e6b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"

async def check_phishtank(url: str) -> dict:
    url_domain = (urlparse(url).hostname or "").lower()
    if _PHISHTANK_FEED_READY and url_domain in _PHISHTANK_FEED_DOMAINS:
        logger.warning("🔴 PhishTank LOCAL FEED: %s", url)
        return {
            "in_database": True,
            "verified": True,
            "valid": True,
            "phish_id": "feed_match",
            "source": "phishtank_feed",
        }

    cache_key = f"pt_{url}"
    cached = _get_cache(cache_key, ttl=_TTL_BLACKLIST)
    if cached:
        return {**cached, "cached": True}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json", "app_key": PHISHTANK_API_KEY},
                headers={"User-Agent": "phishtank/phishguard-angola"},
                follow_redirects=True,
            )
            if r.status_code == 200:
                data = r.json().get("results", {})
                in_db = data.get("in_database", False)
                verified = data.get("verified", False)
                valid = data.get("valid", False)
                result = {
                    "in_database": in_db,
                    "verified": verified,
                    "valid": valid,
                    "phish_id": str(data.get("phish_id")) if data.get("phish_id") else None,
                    "source": "phishtank_api",
                }
                _set_cache(cache_key, result)
                if verified and valid:
                    logger.warning("🔴 PhishTank API CONFIRMED: %s", url)
                return result
    except Exception as e:
        logger.debug("PhishTank API falhou: %s", e)
    return {"in_database": False, "verified": False, "valid": False, "source": "phishtank"}


# ═══════════════════════════════════════════════════════════════════
# VirusTotal (apenas GET, sem submissão)
# ═══════════════════════════════════════════════════════════════════

async def check_virustotal(url: str) -> dict:
    cache_key = f"vt_{url}"
    cached = _get_cache(cache_key)
    if cached:
        return {**cached, "cached": True}

    if not settings.VIRUSTOTAL_API_KEY:
        return {"malicious": 0, "suspicious": 0, "source": "virustotal_skip"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            r = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            )
            if r.status_code == 200:
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "source": "virustotal",
                }
                _set_cache(cache_key, result)
                if result["malicious"] > 0:
                    logger.warning("🔴 VirusTotal: %d engines MALICIOUS for %s", result["malicious"], url)
                return result
            elif r.status_code == 404:
                return {"malicious": 0, "suspicious": 0, "source": "virustotal_not_found"}
    except Exception as e:
        logger.warning(f"VirusTotal failed: {e}")
    return {"malicious": 0, "suspicious": 0, "source": "virustotal_error"}


# ═══════════════════════════════════════════════════════════════════
# Google Safe Browsing
# ═══════════════════════════════════════════════════════════════════

async def check_safe_browsing(url: str) -> dict:
    cache_key = f"gsb_{url}"
    cached = _get_cache(cache_key)
    if cached:
        return {**cached, "cached": True}

    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return {"threat": False, "source": "safe_browsing_skip"}

    payload = {
        "client": {"clientId": "phishguard-angola", "clientVersion": "2.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
            )
            if r.status_code == 200:
                data = r.json()
                matches = data.get("matches", [])
                result = {
                    "threat": bool(matches),
                    "types": [m.get("threatType", "") for m in matches],
                    "source": "safe_browsing",
                }
                _set_cache(cache_key, result)
                if result["threat"]:
                    logger.warning("🔴 Google Safe Browsing THREAT: %s", url)
                return result
    except Exception as e:
        logger.warning(f"Safe Browsing failed: {e}")
    return {"threat": False, "source": "safe_browsing_error"}


# ═══════════════════════════════════════════════════════════════════
# AbuseIPDB
# ═══════════════════════════════════════════════════════════════════

async def check_abuseipdb(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {"abuse_score": 0, "source": "abuseipdb_skip"}

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                if score > 50:
                    logger.warning("🟠 AbuseIPDB: %s score=%d", ip, score)
                return {"abuse_score": score, "total_reports": data.get("totalReports", 0), "source": "abuseipdb"}
    except Exception as e:
        logger.warning(f"AbuseIPDB failed: {e}")
    return {"abuse_score": 0, "source": "abuseipdb_error"}


# ═══════════════════════════════════════════════════════════════════
# DNSBL (SURBL / Spamhaus / URIBL)
# ═══════════════════════════════════════════════════════════════════

DNSBL_ZONES = ["multi.surbl.org", "dbl.spamhaus.org", "uribl.com"]

def check_dnsbl_sync(domain: str) -> dict:
    hits = []
    for zone in DNSBL_ZONES:
        try:
            socket.gethostbyname(f"{domain}.{zone}")
            hits.append(zone)
        except socket.error:
            pass
    return {"flagged": bool(hits), "hits": hits, "source": "dnsbl"}


# ═══════════════════════════════════════════════════════════════════
# Ghost domain / Parked domain / SSL / Domain age
# ═══════════════════════════════════════════════════════════════════

PARKED_PATTERNS = [
    "buy this domain", "domain for sale", "parking", "sedo",
    "godaddy", "this domain is parked", "domain expired",
    "coming soon", "under construction",
]

def check_ghost_domain(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return False
    except socket.error:
        return True

def check_parked_domain(html: str) -> bool:
    if not html:
        return False
    text = html.lower()[:10000]
    for pattern in PARKED_PATTERNS:
        if pattern in text:
            return True
    return False

def check_ssl_cert(domain: str) -> dict:
    """Verifica o certificado SSL. CORRIGIDO timezone‑aware."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"valid": False, "reason": "no_certificate"}
                # As datas vêm em UTC mas sem fuso explícito
                not_after  = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after  = not_after.replace(tzinfo=timezone.utc)
                not_before = not_before.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if now > not_after:
                    return {"valid": False, "reason": "expired"}
                if now < not_before:
                    return {"valid": False, "reason": "not_yet_valid"}
                issuer = dict(x[0] for x in cert["issuer"])
                return {"valid": True, "issuer": issuer.get("organizationName", ""), "expires": not_after.isoformat()}
    except Exception as e:
        return {"valid": False, "reason": str(e)}

def get_domain_age(domain: str) -> int:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = (datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days
            return age
    except Exception:
        pass
    return -1


# ═══════════════════════════════════════════════════════════════════
# URLScan.io (apenas consulta existente)
# ═══════════════════════════════════════════════════════════════════

def _get_urlscan_api_key() -> str:
    return getattr(settings, "URLSCAN_IO", "") or getattr(settings, "URLSCAN_API", "")

async def check_urlscan_existing(url: str) -> dict:
    api_key = _get_urlscan_api_key()
    if not api_key:
        return {"found": False, "malicious": False, "source": "urlscan_skip"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {"API-Key": api_key, "Content-Type": "application/json"}
            r = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f'page.url:"{url}"', "size": 1},
                headers=headers,
            )
            if r.status_code == 200:
                results = r.json().get("results", [])
                if results:
                    verdict = results[0].get("verdicts", {}).get("overall", {})
                    malicious = verdict.get("malicious", False)
                    score = int(verdict.get("score", 0) * 100) if verdict.get("score", 0) <= 1 else verdict.get("score", 0)
                    if malicious:
                        score = max(score, 70)
                        logger.warning("🔴 URLScan.io MALICIOUS: %s", url)
                    return {"found": True, "malicious": malicious, "score": score, "source": "urlscan"}
    except Exception as e:
        logger.warning(f"URLScan.io failed: {e}")
    return {"found": False, "malicious": False, "source": "urlscan_error"}


# ═══════════════════════════════════════════════════════════════════
# COMBINED BLACKLIST CHECK
# ═══════════════════════════════════════════════════════════════════

async def phishing_blacklist_check(url: str) -> dict:
    pt_task = check_phishtank(url)
    urlscan_task = check_urlscan_existing(url)
    pt_result, urlscan_result = await asyncio.gather(pt_task, urlscan_task, return_exceptions=True)

    if isinstance(pt_result, Exception):
        pt_result = {"in_database": False, "verified": False, "valid": False}
    if isinstance(urlscan_result, Exception):
        urlscan_result = {"found": False, "malicious": False}

    blacklisted = False
    score = 0
    reasons = []

    if pt_result.get("verified") and pt_result.get("valid"):
        blacklisted = True
        score = max(score, 98)
        reasons.append(f"PhishTank: URL CONFIRMADA como phishing (ID: {pt_result.get('phish_id', 'N/A')})")
    elif pt_result.get("verified"):
        blacklisted = True
        score = max(score, 92)
        reasons.append("PhishTank: URL verificada como phishing")
    elif pt_result.get("in_database"):
        score = max(score, 70)
        reasons.append("PhishTank: URL na base de dados")

    if urlscan_result.get("malicious"):
        blacklisted = True
        score = max(score, 90)
        reasons.append("URLScan.io: URL maliciosa detectada")

    return {
        "blacklisted": blacklisted,
        "score": min(100, score),
        "reasons": reasons,
        "phishtank": pt_result,
        "urlscan": urlscan_result,
    }
