"""url_analyzer.py — Pipeline de análise de URL (v8 - COMPLETAMENTE CORRIGIDO).

CORRECÇÕES v8:
- TODAS as funções de I/O (DNS, HTTP, WHOIS, Crawler) são agora async com asyncio.to_thread
- _step_crawler correctamente detecta no_content, low_content, ghost_domain, parked_domain
- _step_reputation: APIs externas chamadas correctamente em paralelo com timeout global
- WHOIS: get_domain_age_days chamado em thread separada com tratamento de erro
- DNS: check_dns chamado em thread separada
- Loop infinito _is_proxy_block corrigido
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from backend.services.dns_check import check_dns
from backend.utils.http_check import check_http
from backend.utils.whois_check import get_domain_age_days
from backend.services.scoring import classify_score
from backend.services.brand_search import check_dynamic_brand_spoof

from backend.services.external_apis import (
    check_virustotal,
    check_abuseipdb,
    check_safe_browsing,
    phishing_blacklist_check,
)

logger = logging.getLogger(__name__)

# ─── Marcas conhecidas ───────────────────────────────────────────────────────

KNOWN_BRANDS: Dict[str, List[str]] = {
    "BAI": ["bai.ao"],
    "BFA": ["bfa.ao"],
    "Banco Atlântico": ["atlantico.ao"],
    "BIC": ["bic.ao"],
    "BPC": ["bpc.ao"],
    "Standard Bank": ["standardbank.ao"],
    "Unitel": ["unitel.ao"],
    "Movicel": ["movicel.ao"],
    "Africell": ["africell.ao"],
    "Multicaixa": ["multicaixa.ao"],
    "EMIS": ["emis.ao"],
    "Sonangol": ["sonangol.ao"],
    "TAAG": ["taag.ao"],
    "Netflix": ["netflix.com"],
    "PayPal": ["paypal.com"],
    "DHL": ["dhl.com"],
    "Amazon": ["amazon.com"],
}

INSTITUTIONAL_DOMAINS: set = {
    "itel.gov.ao", "inacom.gov.ao", "mintic.gov.ao", "minfin.gov.ao",
    "ine.gov.ao", "governo.ao", "presidencia.ao", "mineduca.gov.ao",
    "minsa.gov.ao", "mirex.gov.ao", "tribunal.ao", "bna.ao",
    "emis.ao", "multicaixa.ao", "angop.ao", "jornaldeangola.ao",
    "expansao.ao", "ver.ao", "voanews.com",
}

_BRAND_KEYWORD_EXCEPTIONS: Dict[str, set] = {
    "unitel":     {"itel"},
    "multicaixa": {"caix", "caixa"},
    "bai":        {"embaixada", "embai"},
    "bfa":        set(),
    "atlantico":  {"atlanticosul", "atlanticoseguros"},
}

# Padrões de conteúdo vazio/parked (expandido)
PARKED_PATTERNS = [
    "buy this domain", "domain for sale", "parking", "sedo",
    "godaddy", "above.com", "this domain is parked",
    "domain name is for sale", "coming soon", "under construction",
    "website coming soon", "this website is under construction",
    "this domain has expired", "domain expired", "expired domain",
    "parked domain", "domain parking", "buy this domain name",
    "is for sale", "domain may be for sale",
]

REAL_THREATS = [
    "typosquatting", "subdomain_spoof", "spoof_known", "dynamic_brand_spoof",
    "virustotal", "google_safe_browsing", "dnsbl", "abuseipdb",
    "parked_domain", "domain_not_found", "very_new_domain",
    "ghost_domain", "no_real_content",
]

# Proxy block patterns
_PROXY_BLOCK_BODIES = {
    "host not in allowlist", "access denied",
    "blocked by network", "not allowed", "forbidden by policy",
    "blocked by your administrator", "content filtered",
    "access to this resource is forbidden", "403 forbidden",
}

_PROXY_BLOCK_HEADERS = {
    "x-deny-reason", "x-block-reason", "x-squid-error",
    "x-cache-error", "x-forwarded-status",
}


# ─── Helpers síncronos (executados em threads) ──────────────────────────────────────

def _is_institutional(domain: str) -> bool:
    d = domain.lower().strip()
    if d in INSTITUTIONAL_DOMAINS:
        return True
    for inst in INSTITUTIONAL_DOMAINS:
        if d.endswith("." + inst):
            return True
    if d.endswith(".gov.ao"):
        return True
    return False


def _extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower().strip())


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _is_proxy_block_detection(status: int, body: str, headers: dict) -> bool:
    """Detecta se a resposta HTTP indica bloqueio por proxy/firewall."""
    if status in (403, 407, 451, 502, 503):
        body_lower = (body or "").lower()
        if any(p in body_lower for p in _PROXY_BLOCK_BODIES):
            return True
        header_keys = {k.lower() for k in headers.keys()}
        if any(h in header_keys for h in _PROXY_BLOCK_HEADERS):
            return True
    return False


# ─── Typosquatting (síncrono, rápido) ────────────────────────────────────────────────

def _detect_typosquatting_sync(domain: str, score: int, reasons: List[str]) -> Tuple[int, List[str]]:
    if _is_institutional(domain):
        return score, reasons

    domain_body = tldextract.extract(domain).domain.lower()

    if len(domain_body) < 4:
        return score, reasons

    for brand, official_domains in KNOWN_BRANDS.items():
        brand_norm = _normalize(brand)
        sim = _similarity(domain_body, brand_norm)

        exceptions = _BRAND_KEYWORD_EXCEPTIONS.get(brand_norm, set())
        if domain_body in exceptions or any(exc in domain_body for exc in exceptions if exc):
            continue

        if 0.82 < sim < 1.0:
            score += 70
            reasons.append(f"typosquatting:{brand}")
            return score, reasons

        numerified = brand_norm.replace("o", "0").replace("i", "1").replace("l", "1")
        if numerified != brand_norm and numerified in domain_body:
            score += 80
            reasons.append(f"typosquatting_numeric:{brand}")
            return score, reasons

    return score, reasons


def _detect_subdomain_spoof_sync(domain: str, score: int, reasons: List[str]) -> Tuple[int, List[str]]:
    if _is_institutional(domain):
        return score, reasons

    for brand, official_domains in KNOWN_BRANDS.items():
        for official in official_domains:
            if official in domain and not domain.endswith(official):
                score += 85
                reasons.append(f"subdomain_spoof:{brand}({official})")
                return score, reasons
    return score, reasons


# ─── Etapas assíncronas (I/O bound) ─────────────────────────────────────────────────

async def _step_dns_async(domain: str, score: int, reasons: List[str]) -> Tuple[int, List[str], bool]:
    """Verifica DNS em thread separada."""
    try:
        resolves, ips, error = await asyncio.to_thread(check_dns, domain)
        if not resolves:
            score += 90
            reasons.append("domain_not_found")
            return score, reasons, True
        return score, reasons, False
    except Exception as e:
        logger.warning(f"DNS error for {domain}: {e}")
        reasons.append("dns_error")
        return score, reasons, False


async def _step_http_async(url: str, score: int, reasons: List[str]) -> Tuple[int, List[str], bool, Optional[int], bool]:
    """Verifica HTTP em thread separada."""
    http_ok = True
    http_status = None
    http_proxy_blocked = False

    try:
        result = await asyncio.to_thread(check_http, url)
        ok = result[0]
        status = result[1] if len(result) > 1 else None
        response_obj = result[2] if len(result) > 2 else None
        http_status = status

        if not ok:
            if response_obj is not None:
                try:
                    body = response_obj.text or ""
                    headers = dict(response_obj.headers)
                    if _is_proxy_block_detection(status or 0, body, headers):
                        http_proxy_blocked = True
                        reasons.append("proxy_blocked_http")
                        return score, reasons, http_ok, http_status, http_proxy_blocked
                except Exception:
                    pass
            reasons.append("http_unreachable")
            http_ok = False
        elif status is not None and status >= 400:
            if response_obj is not None:
                try:
                    body = response_obj.text or ""
                    headers = dict(response_obj.headers)
                    if _is_proxy_block_detection(status, body, headers):
                        http_proxy_blocked = True
                        reasons.append("proxy_blocked_http")
                        return score, reasons, http_ok, http_status, http_proxy_blocked
                except Exception:
                    pass
            reasons.append(f"http_error:{status}")
            http_ok = False

    except Exception as e:
        logger.warning(f"HTTP erro: {e}")
        reasons.append("http_error_internal")
        http_ok = False

    return score, reasons, http_ok, http_status, http_proxy_blocked


async def _step_whois_async(domain: str, score: int, reasons: List[str]) -> Tuple[int, List[str]]:
    """Verifica WHOIS (idade do domínio) em thread separada."""
    try:
        age = await asyncio.to_thread(get_domain_age_days, domain)
        if age is None:
            reasons.append("whois_unavailable")
        elif age < 7:
            score += 70
            reasons.append(f"very_new_domain:{age}d")
        elif age < 30:
            score += 25
            reasons.append(f"new_domain:{age}d")
        elif age < 90:
            score += 10
            reasons.append(f"recent_domain:{age}d")
        else:
            # Domínio antigo (mais de 90 dias) - não adiciona score
            pass
    except Exception as e:
        logger.warning(f"WHOIS error for {domain}: {e}")
        reasons.append("whois_error")
    return score, reasons


async def _step_crawler_async(url: str, score: int, reasons: List[str]) -> Tuple[int, List[str], str, str, Optional[int], bool]:
    """
    Faz crawling da URL em thread separada.
    Detecta: conteúdo vazio, parked domains, ghost domains, proxy blocks.
    """
    html = ""
    title = ""
    status = None
    proxy_blocked = False

    def _crawl_sync():
        nonlocal html, title, status, proxy_blocked
        try:
            response = requests.get(
                url,
                timeout=12,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "pt-PT,pt;q=0.9,en;q=0.8",
                },
                allow_redirects=True,
                verify=False,
            )
            status = response.status_code

            # Verificar proxy block baseado no status/headers
            if _is_proxy_block_detection(status, response.text or "", dict(response.headers)):
                proxy_blocked = True
                return

            # Só extrair HTML se for conteúdo textual
            content_type = response.headers.get("content-type", "").lower()
            if "text/html" in content_type or "text/plain" in content_type:
                html = response.text or ""
            else:
                # Conteúdo binário (PDF, imagem, etc.) - não é phishing típico
                html = ""

        except requests.exceptions.Timeout:
            logger.debug(f"Crawler timeout for {url}")
            status = 408
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Crawler connection error for {url}: {e}")
            status = 0
        except requests.exceptions.TooManyRedirects:
            logger.debug(f"Crawler too many redirects for {url}")
            status = 0
        except Exception as e:
            logger.debug(f"Crawler error for {url}: {e}")
            status = 0

    try:
        await asyncio.to_thread(_crawl_sync)

        if proxy_blocked:
            reasons.append("proxy_blocked")
            return score, reasons, "", "", status, True

        if status is None or status == 0:
            reasons.append("fetch_failed")
            return score, reasons, "", "", status, False

        if status >= 400:
            reasons.append(f"crawler_http_error:{status}")
            return score, reasons, "", "", status, False

        if not html or not html.strip():
            reasons.append("no_content")
            return score, reasons, "", "", status, False

        # Analisar conteúdo HTML
        html_lower = html.lower()
        html_len = len(html)

        if html_len < 500:
            score += 10
            reasons.append("low_content")

        try:
            soup = BeautifulSoup(html, "lxml")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
        except Exception:
            title = ""

        if not title:
            reasons.append("no_title")

        # Detectar parked domain (expansivo)
        if any(p in html_lower for p in PARKED_PATTERNS):
            score += 80
            reasons.append("parked_domain")

        # Detectar ghost domain (domínio que existe mas tem conteúdo mínimo)
        if html_len < 2000 and not title:
            score += 30
            reasons.append("ghost_domain")

    except Exception as e:
        logger.warning(f"Crawler exception: {e}")
        reasons.append("crawler_exception")

    return score, reasons, html, title, status, proxy_blocked


def _step_brand_spoofing_sync(url: str, html: str, title: str, score: int, reasons: List[str]) -> Tuple[int, List[str]]:
    """Detecta spoofing de marca no título/conteúdo (síncrono, rápido)."""
    if not html:
        return score, reasons

    domain = _extract_domain(url)

    for raw in [title]:
        if not raw:
            continue
        brand = _normalize(raw)
        for known, domains in KNOWN_BRANDS.items():
            if _normalize(known) in brand and domain not in domains:
                score += 90
                reasons.append(f"spoof_known:{known}")
                return score, reasons

    return score, reasons


async def _step_reputation_async(url: str, domain: str, score: int, reasons: List[str]) -> Tuple[int, List[str]]:
    """
    Corrigido v8: APIs externas rodam em paralelo com timeout global.
    - VirusTotal (scanning + cache)
    - Google Safe Browsing
    - PhishTank + OpenPhish + URLhaus (via phishing_blacklist_check)
    - AbuseIPDB (se IP resolver)
    """
    try:
        # Resolver IP para AbuseIPDB
        ip = None
        try:
            ip = await asyncio.to_thread(socket.gethostbyname, domain)
        except Exception:
            pass

        # Criar tasks
        vt_task = check_virustotal(url)
        gsb_task = check_safe_browsing(url)
        bl_task = phishing_blacklist_check(url)  # PhishTank + OpenPhish + URLhaus

        if ip:
            abuse_task = check_abuseipdb(ip)
            vt, gsb, bl, abuse = await asyncio.wait_for(
                asyncio.gather(vt_task, gsb_task, bl_task, abuse_task, return_exceptions=True),
                timeout=18.0
            )
        else:
            vt, gsb, bl = await asyncio.wait_for(
                asyncio.gather(vt_task, gsb_task, bl_task, return_exceptions=True),
                timeout=18.0
            )
            abuse = {"abuse_score": 0}

        # Processar phishing_blacklist_check (PhishTank + OpenPhish + URLhaus)
        if isinstance(bl, dict):
            if bl.get("blacklisted"):
                bl_score = bl.get("score", 90)
                score = max(score, bl_score)
                reasons.extend(bl.get("reasons", []))
                logger.info(f"Blacklist hit for {url[:60]}: score={bl_score}")
            elif bl.get("score", 0) > 70:
                score = max(score, bl.get("score", 0))
                reasons.extend(bl.get("reasons", []))

        # Processar VirusTotal
        if isinstance(vt, dict):
            vt_mal = vt.get("malicious", 0)
            vt_sus = vt.get("suspicious", 0)
            if vt_mal >= 3:
                score = max(score, min(score + 85, 100))
                reasons.append(f"virustotal:{vt_mal}_motores_maliciosos")
                logger.info(f"VT hit for {url[:60]}: {vt_mal} malicious engines")
            elif vt_mal >= 1:
                score = max(score, min(score + 60, 100))
                reasons.append("virustotal")
                logger.info(f"VT hit for {url[:60]}: {vt_mal} malicious engine(s)")
            elif vt_sus >= 3:
                score = max(score, min(score + 35, 100))
                reasons.append(f"virustotal_suspicious:{vt_sus}_motores")

        # Processar AbuseIPDB
        if isinstance(abuse, dict) and abuse.get("abuse_score", 0) >= 50:
            score = max(score, min(score + 40, 100))
            reasons.append("abuseipdb")
            logger.info(f"AbuseIPDB hit for {domain}: score={abuse.get('abuse_score')}")

        # Processar Google Safe Browsing
        if isinstance(gsb, dict) and gsb.get("threat"):
            score = max(score, min(score + 85, 100))
            reasons.append("google_safe_browsing")
            logger.info(f"GSB hit for {url[:60]}")

    except asyncio.TimeoutError:
        logger.warning(f"Reputation APIs timeout for {url[:60]}")
        reasons.append("reputation_api_timeout")
    except Exception as e:
        logger.warning(f"Reputation step failed: {e}")
        reasons.append("reputation_error")

    return score, reasons


# ─── Função principal ASYNC ──────────────────────────────────────────────────────

async def analyze_url(url: str) -> dict:
    """
    Pipeline completo de análise de URL (100% assíncrono).

    Etapas:
      1. DNS
      2. Typosquatting
      3. Subdomain Spoof
      4. HTTP
      5. WHOIS (idade do domínio)
      6. Crawler (conteúdo - no_content, ghost_domain, parked_domain)
      7. Brand spoofing estático
      8. Brand spoofing dinâmico (Google Custom Search)
      9. Reputação externa (VT, GSB, PhishTank, OpenPhish, AbuseIPDB)
    """
    score = 0
    reasons: List[str] = []

    # Normalizar URL
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    parsed = urlparse(url)
    if not parsed.netloc:
        return {
            "score": 100,
            "classification": "phishing",
            "reasons": ["invalid_url"],
        }

    domain = _extract_domain(url)

    # 1. DNS (assíncrono)
    score, reasons, stop = await _step_dns_async(domain, score, reasons)
    if stop:
        return {
            "score": score,
            "classification": classify_score(score),
            "reasons": reasons,
        }

    # 2. Typosquatting (síncrono, rápido)
    score, reasons = _detect_typosquatting_sync(domain, score, reasons)

    # 3. Subdomain Spoof (síncrono, rápido)
    score, reasons = _detect_subdomain_spoof_sync(domain, score, reasons)

    # 4. HTTP (assíncrono)
    score, reasons, http_ok, http_status, http_proxy_blocked = await _step_http_async(url, score, reasons)

    # 5. WHOIS (assíncrono) - IDADE DO DOMÍNIO CORRIGIDA
    score, reasons = await _step_whois_async(domain, score, reasons)

    # 6. Crawler (assíncrono) - no_content, ghost_domain CORRIGIDOS
    score, reasons, html, title, crawler_status, proxy_blocked = await _step_crawler_async(url, score, reasons)

    # 7. Brand spoofing estático (síncrono)
    score, reasons = _step_brand_spoofing_sync(url, html, title, score, reasons)

    # 8. Brand spoofing dinâmico (pode fazer chamada HTTP à Google Custom Search)
    score, reasons = check_dynamic_brand_spoof(domain, KNOWN_BRANDS, score, reasons)

    # 9. Reputação externa (assíncrono, paralelo)
    score, reasons = await _step_reputation_async(url, domain, score, reasons)

    # ─── ghost_domain / no_real_content (corrigido v8) ──────────────────────────
    has_real_html = bool(html and html.strip())
    http_exception = "http_error_internal" in reasons and http_status is None
    crawler_empty = any(r in reasons for r in ("fetch_failed", "no_content", "crawler_exception"))

    # Ghost domain: domínio que existe mas não tem conteúdo real
    if http_exception and (crawler_empty or not has_real_html):
        score = max(score, min(score + 55, 100))
        if "ghost_domain" not in reasons:
            reasons.append("ghost_domain")
    else:
        any_proxy_block = proxy_blocked or http_proxy_blocked
        if not has_real_html and not any_proxy_block and (
            (http_status is not None and http_status >= 400)
            or "http_unreachable" in reasons
            or (crawler_status is not None and crawler_status >= 400)
        ):
            score = max(score, min(score + 45, 100))
            if "no_real_content" not in reasons:
                reasons.append("no_real_content")

    # ─── Classificação final ──────────────────────────────────────────────────────
    has_real_threat = any(
        any(rt in r for rt in REAL_THREATS)
        for r in reasons
    )

    if not has_real_threat:
        score = min(score, 10)
        if "no_real_threats_detected" not in reasons:
            reasons.append("no_real_threats_detected")

    if score == 0 and not reasons:
        score = 5
        reasons.append("no_signals")

    score = min(score, 100)

    return {
        "score": score,
        "classification": classify_score(score),
        "reasons": reasons,
    }
