"""
backend/services/url_analyzer.py
──────────────────────────────────
Pipeline de análise de URL v17 — PhishGuard Angola

CORRECÇÕES v17:
- REMOVIDA a penalização por TLD suspeito (lista estática era ineficiente)
- Apenas TLDs governamentais/educacionais recebem BÓNUS de confiança
- Todos os outros TLDs (.com, .org, .net, .io, .xyz, .tk, .ml, etc.)
  são NEUTROS — não afetam o score
- O score agora depende APENAS de:
  1. Blacklists (PhishTank, OpenPhish, URLScan)
  2. VirusTotal + Google Safe Browsing
  3. Typosquatting de marcas conhecidas
  4. DNS inválido / IP direto / @ na URL
  5. Conteúdo de phishing na página
  6. Hosting suspeito (wixsite, netlify, github.io, etc.)
  7. Domínios estacionados (parked)
"""

from __future__ import annotations

import asyncio
import logging
import re
from difflib import SequenceMatcher
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import tldextract
import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from backend.services.dns_check import check_dns
from backend.services.scoring import classify_score
from backend.services.brand_search import check_dynamic_brand_spoof

from backend.services.external_apis import (
    check_virustotal,
    check_abuseipdb,
    check_safe_browsing,
    phishing_blacklist_check,
)

logger = logging.getLogger(__name__)

MAX_HEURISTIC_SCORE = 55
BLACKLIST_BLOCK_SCORE = 90
VIRUSTOTAL_BLOCK_SCORE = 75
SAFE_BROWSING_BLOCK_SCORE = 85

ALWAYS_SAFE_DOMAINS: set[str] = {
    "google.com", "google.co.ao", "google.pt", "google.com.br",
    "google.co.uk", "google.fr", "google.de", "google.es",
    "google.it", "google.nl", "google.pl", "google.co.jp",
    "google.co.in", "google.com.au", "google.com.mx",
    "googleapis.com", "gstatic.com", "googleusercontent.com",
    "bing.com", "yahoo.com", "duckduckgo.com",
    "yandex.com", "baidu.com", "ecosia.org",
    "youtube.com", "youtu.be",
    "gmail.com", "mail.google.com",
    "drive.google.com", "docs.google.com",
    "accounts.google.com", "myaccount.google.com",
    "play.google.com", "news.google.com",
    "maps.google.com", "photos.google.com",
    "meet.google.com", "calendar.google.com",
    "microsoft.com", "live.com", "outlook.com",
    "hotmail.com", "office.com", "office365.com",
    "onedrive.com", "microsoftonline.com",
    "teams.microsoft.com",
    "apple.com", "icloud.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "tiktok.com", "meta.com",
    "snapchat.com", "pinterest.com", "reddit.com",
    "linkedin.com", "telegram.org", "discord.com",
    "slack.com", "zoom.us", "messenger.com",
    "protonmail.com", "mail.yahoo.com", "mail.ru", "yandex.ru",
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
    "ebay.com", "aliexpress.com",
    "mercadolivre.com.br", "olx.pt",
    "nike.com", "adidas.com", "puma.com",
    "zara.com", "hm.com", "ikea.com",
    "netflix.com", "spotify.com", "disneyplus.com",
    "primevideo.com", "hbomax.com", "hulu.com",
    "bbc.com", "cnn.com", "reuters.com",
    "nytimes.com", "theguardian.com",
    "angop.ao", "jornaldeangola.ao",
    "bai.ao", "bfa.ao", "bic.ao", "bpc.ao",
    "unitel.ao", "movicel.ao", "africell.ao",
    "multicaixa.ao", "emis.ao", "sonangol.ao",
    "taag.ao", "governo.ao", "bna.ao",
    "atlantico.ao", "standardbank.ao",
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "medium.com",
    "wikipedia.org", "wikimedia.org",
    "paypal.com", "stripe.com", "shopify.com",
    "visa.com", "mastercard.com",
    "phishtank.com", "phishtank.net", "phishtank.org",
    "virustotal.com", "urlscan.io",
    "abuseipdb.com", "abuse.ch",
    "talosintelligence.com", "openphish.com",
    "spamhaus.org",
    "chatgpt.com", "openai.com",
    "deepseek.com", "chat.deepseek.com",
    "claude.ai", "anthropic.com", "perplexity.ai",
    "dropbox.com", "wetransfer.com",
    "canva.com", "figma.com", "adobe.com",
    "notion.so", "trello.com", "asana.com",
    "salesforce.com", "hubspot.com",
    "dhl.com", "fedex.com", "ups.com",
    "wix.com", "wordpress.com",
}

KNOWN_BRANDS: Dict[str, List[str]] = {
    "BAI": ["bai.ao", "baionline.ao"],
    "BFA": ["bfa.ao", "bfaonline.ao"],
    "Banco Atlântico": ["atlantico.ao"],
    "BIC": ["bic.ao", "bicnet.ao"],
    "BPC": ["bpc.ao"],
    "Standard Bank": ["standardbank.ao"],
    "Unitel": ["unitel.ao"],
    "Movicel": ["movicel.ao"],
    "Africell": ["africell.ao"],
    "Multicaixa": ["multicaixa.ao", "emis.ao"],
    "EMIS": ["emis.ao"],
    "Sonangol": ["sonangol.ao"],
    "TAAG": ["taag.ao"],
    "Netflix": ["netflix.com"],
    "PayPal": ["paypal.com"],
    "DHL": ["dhl.com"],
    "Amazon": ["amazon.com"],
    "Google": ["google.com"],
    "Microsoft": ["microsoft.com"],
    "Apple": ["apple.com"],
    "Facebook": ["facebook.com"],
}

PARKED_PATTERNS = [
    "buy this domain", "domain for sale", "parking", "sedo",
    "godaddy", "this domain is parked", "domain expired",
    "coming soon", "under construction",
]

# ─── Helpers ──────────────────────────────────────────────────────

def _normalize_domain(domain: str) -> str:
    """Remove www. e outros prefixos comuns para normalização."""
    d = domain.lower().strip()
    for prefix in ["www.", "ww2.", "web.", "mail.", "secure.", "login."]:
        if d.startswith(prefix):
            d = d[len(prefix):]
            break
    return d


def _is_always_safe(domain: str) -> bool:
    """Verifica se o domínio é de um serviço conhecido e SEMPRE seguro."""
    d = _normalize_domain(domain)
    if d in ALWAYS_SAFE_DOMAINS:
        return True
    for safe in ALWAYS_SAFE_DOMAINS:
        if d.endswith("." + safe) or d == safe:
            return True
    return False


def _is_government_or_educational(domain: str) -> bool:
    """
    Detecta dinamicamente domínios governamentais/educacionais/militares.
    
    Procura por "gov", "edu", "mil", "ac", "int" em qualquer parte do TLD.
    Exemplos: .gov.ao, .gov.br, .gov.uk, .edu, .ac.uk, .mil, .int
    
    NÃO usa lista estática de países — funciona para qualquer país.
    """
    d = _normalize_domain(domain)
    parts = d.split(".")
    for part in parts[1:]:  # ignora o nome do domínio
        if part in ("gov", "edu", "mil", "ac", "int"):
            return True
    return False


def _extract_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return ext.domain.lower()
    except:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower().strip())


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


_BRAND_KEYWORD_EXCEPTIONS: Dict[str, set] = {
    "unitel": {"itel"},
    "multicaixa": {"caix", "caixa"},
    "bai": {"embaixada", "embai"},
    "atlantico": {"atlanticosul", "atlanticoseguros"},
}


def _detect_typosquatting(domain: str) -> Tuple[int, List[str]]:
    d = _normalize_domain(domain)
    domain_body = tldextract.extract(d).domain.lower()
    if len(domain_body) < 4:
        return 0, []
    
    for brand, official_domains in KNOWN_BRANDS.items():
        brand_norm = _normalize(brand)
        sim = _similarity(domain_body, brand_norm)
        
        exceptions = _BRAND_KEYWORD_EXCEPTIONS.get(brand_norm, set())
        if domain_body in exceptions or any(exc in domain_body for exc in exceptions if exc):
            continue
        
        if 0.85 < sim < 1.0 and len(domain_body) >= len(brand_norm) - 1:
            return 40, [f"typosquatting:{brand}"]
        
        numerified = brand_norm.replace("o", "0").replace("i", "1").replace("l", "1")
        if numerified != brand_norm and numerified in domain_body:
            return 45, [f"typosquatting_numeric:{brand}"]
    
    return 0, []


def _detect_subdomain_spoof(domain: str) -> Tuple[int, List[str]]:
    d = _normalize_domain(domain)
    for brand, official_domains in KNOWN_BRANDS.items():
        for official in official_domains:
            if official in d and not d.endswith(official):
                domain_parts = d.split(".")
                official_parts = official.split(".")
                if official_parts[0] in domain_parts and d != official:
                    return 50, [f"subdomain_spoof:{brand}({official})"]
    return 0, []


# ═══════════════════════════════════════════════════════════════════
# FUNÇÃO PRINCIPAL v17
# ═══════════════════════════════════════════════════════════════════

async def analyze_url(url: str) -> dict:
    """
    Pipeline de análise de URL v17.
    
    LÓGICA DE SCORE:
    - Blacklists → score máximo (90+)
    - Typosquatting → +40-50
    - DNS inválido → +30
    - IP direto → +40
    - @ na URL → +35
    - Conteúdo phishing → +25
    - Hosting suspeito → +20
    - Domínio estacionado → +45
    - Domínio governamental/educacional → bónus (reduz score)
    - TLD NÃO afeta o score (nem para mais, nem para menos)
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    parsed = urlparse(url)
    if not parsed.netloc:
        return {"score": 100, "classification": "phishing", "reasons": ["invalid_url"]}
    
    domain = _extract_domain(url)
    hostname = parsed.hostname or ""
    normalized_domain = _normalize_domain(domain)
    
    # ═══════════════════════════════════════════════════════════════
    # VERIFICAÇÃO RÁPIDA: Domínio conhecido?
    # ═══════════════════════════════════════════════════════════════
    if _is_always_safe(domain) or _is_always_safe(normalized_domain):
        logger.info(f"✅ Domínio seguro conhecido: {domain}")
        return {
            "score": 5,
            "classification": "safe",
            "reasons": ["trusted_domain"],
        }
    
    logger.info(f"🔍 Analisando: {url[:100]} (domínio: {domain})")
    
    # ═══════════════════════════════════════════════════════════════
    # FASE 1: HEURÍSTICAS (apenas sinais concretos de phishing)
    # ═══════════════════════════════════════════════════════════════
    heuristic_score = 0
    heuristic_reasons: List[str] = []
    
    # 1. DNS
    try:
        resolves, ips, dns_error = await asyncio.wait_for(
            asyncio.to_thread(check_dns, domain),
            timeout=5.0
        )
        if not resolves:
            heuristic_score += 30
            heuristic_reasons.append(f"domain_not_found:{dns_error}")
    except:
        pass
    
    # 2. IP direto
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        heuristic_score += 40
        heuristic_reasons.append("IP direto na URL")
    
    # 3. Símbolo @
    if "@" in parsed.path or "@" in parsed.netloc:
        heuristic_score += 35
        heuristic_reasons.append("Símbolo @ na URL")
    
    # 4. Typosquatting
    typo_score, typo_reasons = _detect_typosquatting(normalized_domain)
    if typo_score > 0:
        heuristic_score += typo_score
        heuristic_reasons.extend(typo_reasons)
    
    # 5. Subdomain Spoof
    spoof_score, spoof_reasons = _detect_subdomain_spoof(normalized_domain)
    if spoof_score > 0:
        heuristic_score += spoof_score
        heuristic_reasons.extend(spoof_reasons)
    
    # 6. Domínio governamental/educacional → bónus
    is_gov_edu = _is_government_or_educational(normalized_domain)
    
    # 7. HTTP + Conteúdo
    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                requests.get, url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                timeout=10, allow_redirects=True, verify=False,
            ),
            timeout=12.0
        )
        
        http_status = response.status_code
        html = response.text
        
        if http_status >= 500:
            heuristic_score += 15
            heuristic_reasons.append(f"http_error:{http_status}")
        
        if html and len(html) > 100:
            html_lower = html[:10000].lower()
            
            for pattern in PARKED_PATTERNS:
                if pattern in html_lower:
                    heuristic_score += 45
                    heuristic_reasons.append("parked_domain")
                    break
            
            phishing_content = [
                "verify your wallet", "restore your wallet",
                "seed phrase", "private key", "recovery phrase",
                "import wallet", "connect wallet",
            ]
            found_kw = [k for k in phishing_content if k in html_lower]
            if len(found_kw) >= 2:
                heuristic_score += 25
                heuristic_reasons.append("phishing_content_detected")
            
            suspicious_hosting = [
                "wixstudio.com", "wixsite.com", "netlify.app", "github.io",
                "vercel.app", "pages.dev", "glitch.me", "000webhost.com",
                "weebly.com", "firebaseapp.com", "web.app", "ngrok.io",
            ]
            for host in suspicious_hosting:
                if host in normalized_domain:
                    heuristic_score += 20
                    heuristic_reasons.append(f"hosting_gratuito:{host}")
                    break
                    
        elif html and len(html) <= 100:
            heuristic_score += 30
            heuristic_reasons.append("no_content")
    except:
        pass
    
    # 8. Muitos hífens
    if hostname.count("-") >= 3:
        heuristic_score += 10
        heuristic_reasons.append("muitos_hifens")
    
    # 9. Domínio muito longo
    if len(hostname) > 40:
        heuristic_score += 10
        heuristic_reasons.append("dominio_muito_longo")
    
    if heuristic_score > MAX_HEURISTIC_SCORE:
        heuristic_score = MAX_HEURISTIC_SCORE
    
    # ═══════════════════════════════════════════════════════════════
    # FASE 2: EVIDÊNCIAS EXTERNAS
    # ═══════════════════════════════════════════════════════════════
    external_score = 0
    external_reasons: List[str] = []
    has_concrete_evidence = False
    
    try:
        bl_task = phishing_blacklist_check(url)
        vt_task = check_virustotal(url)
        gsb_task = check_safe_browsing(url)
        
        bl_result, vt_result, gsb_result = await asyncio.wait_for(
            asyncio.gather(bl_task, vt_task, gsb_task, return_exceptions=True),
            timeout=20.0
        )
        
        if isinstance(bl_result, dict):
            if bl_result.get("blacklisted"):
                external_score = max(external_score, BLACKLIST_BLOCK_SCORE)
                external_reasons.extend(bl_result.get("reasons", []))
                has_concrete_evidence = True
            elif bl_result.get("score", 0) >= 60:
                external_score = max(external_score, bl_result["score"])
                external_reasons.extend(bl_result.get("reasons", []))
                has_concrete_evidence = True
        
        if isinstance(vt_result, dict):
            vt_mal = vt_result.get("malicious", 0)
            if vt_mal >= 3:
                external_score = max(external_score, VIRUSTOTAL_BLOCK_SCORE)
                external_reasons.append(f"virustotal:{vt_mal}_engines")
                has_concrete_evidence = True
        
        if isinstance(gsb_result, dict) and gsb_result.get("threat"):
            external_score = max(external_score, SAFE_BROWSING_BLOCK_SCORE)
            external_reasons.append("google_safe_browsing:ameaça")
            has_concrete_evidence = True
    
    except asyncio.TimeoutError:
        logger.warning(f"APIs timeout for {url}")
    except Exception as e:
        logger.warning(f"APIs error: {e}")
    
    # ═══════════════════════════════════════════════════════════════
    # FASE 3: DECISÃO FINAL
    # ═══════════════════════════════════════════════════════════════
    
    if has_concrete_evidence:
        final_score = max(external_score, heuristic_score)
        final_reasons = external_reasons + heuristic_reasons
    elif external_score > 0:
        final_score = max(heuristic_score, external_score)
        final_reasons = external_reasons + heuristic_reasons
    elif heuristic_score > 0:
        final_score = heuristic_score
        final_reasons = heuristic_reasons
        
        # Bónus: domínio governamental/educacional com score baixo → SEGURO
        if is_gov_edu and final_score < 40:
            final_score = 5
            final_reasons = ["trusted_domain"]
    else:
        final_score = 5
        final_reasons = ["no_threats_detected"]
    
    if not final_reasons:
        final_reasons = ["no_threats_detected"]
        final_score = 5
    
    final_score = min(100, max(0, final_score))
    
    result = {
        "score": final_score,
        "classification": classify_score(final_score),
        "reasons": final_reasons,
    }
    
    logger.info(
        f"📊 Resultado: {url[:80]} → score={final_score}, "
        f"classification={result['classification']}"
    )
    
    return result
