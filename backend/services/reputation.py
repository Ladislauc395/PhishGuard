"""Integração com APIs externas de reputação: VirusTotal, AbuseIPDB, Google Safe Browsing e blacklists DNS."""

from __future__ import annotations

import base64
import logging
import os
import socket
from dataclasses import dataclass, field
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY        = os.getenv("ABUSEIPDB_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

REQUEST_TIMEOUT = 8

# ─── Blacklists DNS (SURBL / Spamhaus / URIBL) ───────────────────
# Consultadas via DNS: <domínio>.<zona-blacklist>
# Se resolver → domínio está listado como malicioso.
DNSBL_ZONES = [
    "multi.surbl.org",   # SURBL — URLs em spam
    "dbl.spamhaus.org",  # Spamhaus DBL — domínios maliciosos/spam
    "uribl.com",         # URIBL — domínios em mensagens de spam
]


@dataclass
class ReputationResult:
    virustotal_flagged: bool           = False
    abuseipdb_flagged: bool            = False
    abuseipdb_score: int               = 0
    google_safe_browsing_flagged: bool = False  # NOVO
    dnsbl_flagged: bool                = False  # NOVO
    dnsbl_hits: List[str]              = field(default_factory=list)  # NOVO
    errors: List[str]                  = field(default_factory=list)


# ─── VirusTotal ───────────────────────────────────────────────────

def check_virustotal(url: str) -> tuple[bool, Optional[str]]:
    if not VIRUSTOTAL_API_KEY:
        return False, "VIRUSTOTAL_API_KEY não configurada"

    try:
        url_id  = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 404:
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=REQUEST_TIMEOUT,
            )
            return False, None

        resp.raise_for_status()
        data      = resp.json()
        stats     = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        return malicious > 0, None

    except requests.exceptions.RequestException as exc:
        return False, f"VirusTotal erro: {exc}"


# ─── AbuseIPDB ────────────────────────────────────────────────────

def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def check_abuseipdb(domain: str) -> tuple[bool, int, Optional[str]]:
    if not ABUSEIPDB_API_KEY:
        return False, 0, "ABUSEIPDB_API_KEY não configurada"

    ip = _resolve_ip(domain)
    if not ip:
        return False, 0, "Erro ao resolver IP"

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=REQUEST_TIMEOUT,
        )

        resp.raise_for_status()
        data  = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        return score > 50, score, None

    except requests.exceptions.RequestException as exc:
        return False, 0, f"AbuseIPDB erro: {exc}"


# ─── Google Safe Browsing ─────────────────────────────────────────
# Verifica se a URL consta nas listas de phishing/malware da Google.
# API gratuita — requer chave em GOOGLE_SAFE_BROWSING_API_KEY.
# Docs: https://developers.google.com/safe-browsing/v4/lookup-api

def check_google_safe_browsing(url: str) -> tuple[bool, Optional[str]]:
    """
    Retorna (flagged, error).
    flagged=True se a URL estiver em qualquer lista de ameaças da Google.
    """
    if not GOOGLE_SAFE_BROWSING_KEY:
        return False, "GOOGLE_SAFE_BROWSING_API_KEY não configurada"

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={GOOGLE_SAFE_BROWSING_KEY}"
    )

    payload = {
        "client": {
            "clientId":      "phishguard",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",          # phishing
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        # Resposta vazia → URL segura; "matches" presente → URL maliciosa
        flagged = bool(data.get("matches"))
        return flagged, None

    except requests.exceptions.RequestException as exc:
        return False, f"Google Safe Browsing erro: {exc}"


# ─── Blacklists DNS (SURBL / Spamhaus / URIBL) ───────────────────
# Técnica: consulta DNS tipo A para <domínio>.<zona-blacklist>.
# Se o lookup devolver qualquer IP → domínio está listado.

def _dnsbl_lookup(domain: str, zone: str) -> bool:
    """Devolve True se o domínio estiver listado na zona DNSBL."""
    query = f"{domain}.{zone}"
    try:
        socket.getaddrinfo(query, None)
        return True   # resolveu → está na blacklist
    except socket.gaierror:
        return False  # NXDOMAIN ou timeout → não listado


def check_dnsbl(domain: str) -> tuple[bool, List[str]]:
    """
    Verifica domínio contra todas as zonas DNSBL configuradas.

    Returns:
        (flagged, hits) — hits é a lista de zonas onde o domínio foi encontrado.
    """
    hits: List[str] = []

    for zone in DNSBL_ZONES:
        try:
            if _dnsbl_lookup(domain, zone):
                hits.append(zone)
                logger.info("DNSBL hit: %s em %s", domain, zone)
        except Exception as exc:
            logger.debug("DNSBL lookup falhou para %s/%s: %s", domain, zone, exc)

    return bool(hits), hits


# ─── Entrada unificada ────────────────────────────────────────────

def check_reputation(url: str, domain: str) -> ReputationResult:
    result = ReputationResult()

    # VirusTotal
    vt_flagged, vt_err = check_virustotal(url)
    if vt_err:
        result.errors.append(vt_err)
    result.virustotal_flagged = vt_flagged

    # AbuseIPDB
    abuse_flagged, abuse_score, abuse_err = check_abuseipdb(domain)
    if abuse_err:
        result.errors.append(abuse_err)
    result.abuseipdb_flagged = abuse_flagged
    result.abuseipdb_score   = abuse_score

    # Google Safe Browsing (NOVO)
    gsb_flagged, gsb_err = check_google_safe_browsing(url)
    if gsb_err:
        result.errors.append(gsb_err)
    result.google_safe_browsing_flagged = gsb_flagged

    # Blacklists DNS — SURBL, Spamhaus, URIBL (NOVO)
    dnsbl_flagged, dnsbl_hits = check_dnsbl(domain)
    result.dnsbl_flagged = dnsbl_flagged
    result.dnsbl_hits    = dnsbl_hits

    return result
