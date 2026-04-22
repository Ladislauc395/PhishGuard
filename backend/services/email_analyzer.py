"""Serviço para análise heurística de e-mails (SPF/DKIM/DMARC + links)."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from email.parser import Parser
from typing import Dict, List

from backend.models.brand import BrandProfile
from backend.services.heuristics import extract_domain

logger = logging.getLogger(__name__)

LINK_REGEX = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)


@dataclass(slots=True)
class EmailAnalysisResult:
    spf_pass: bool
    dkim_pass: bool
    dmarc_pass: bool
    urls_found: List[str]
    suspicious_link_detected: bool
    details: Dict[str, str | bool | list[str]]


def _header_has_pass(header_value: str) -> bool:
    normalized = (header_value or "").lower()
    return "pass" in normalized and "fail" not in normalized


def _header_has_fail(header_value: str) -> bool:
    normalized = (header_value or "").lower()
    return "fail" in normalized or "none" in normalized or "softfail" in normalized


def parse_email_headers(raw_headers: str) -> Dict[str, str]:
    """Faz parse de headers RFC822 para dicionário plano."""
    parser = Parser()
    message = parser.parsestr(raw_headers or "")

    parsed: Dict[str, str] = {}
    for key in message.keys():
        parsed[key.lower()] = message.get(key, "")
    return parsed


def analyze_email_authentication(raw_headers: str) -> tuple[bool, bool, bool, Dict[str, str]]:
    """Extrai status SPF/DKIM/DMARC a partir de Authentication-Results e headers correlatos."""
    parsed = parse_email_headers(raw_headers)

    auth_results = parsed.get("authentication-results", "")
    received_spf = parsed.get("received-spf", "")
    dkim_signature = parsed.get("dkim-signature", "")

    spf_pass = _header_has_pass(auth_results) or _header_has_pass(received_spf)
    dkim_pass = _header_has_pass(auth_results) or bool(dkim_signature)
    dmarc_pass = "dmarc=pass" in auth_results.lower()

    if _header_has_fail(auth_results) or _header_has_fail(received_spf):
        if "spf=fail" in auth_results.lower() or "spf=none" in auth_results.lower() or _header_has_fail(received_spf):
            spf_pass = False
        if "dkim=fail" in auth_results.lower() or "dkim=none" in auth_results.lower():
            dkim_pass = False
        if "dmarc=fail" in auth_results.lower() or "dmarc=none" in auth_results.lower():
            dmarc_pass = False

    return spf_pass, dkim_pass, dmarc_pass, parsed


def find_urls_in_email(body: str | None, headers: str | None) -> List[str]:
    """Extrai links no corpo e, se necessário, nos headers."""
    combined = f"{body or ''}\n{headers or ''}"
    return LINK_REGEX.findall(combined)


def has_suspicious_links(urls: List[str], brands: List[BrandProfile]) -> bool:
    """Marca como suspeito quando link contém marca mas não usa domínio oficial."""
    for url in urls:
        domain = extract_domain(url)
        if not domain:
            continue
        for brand in brands:
            brand_keywords = [k.lower().replace(" ", "") for k in brand.keywords]
            if any(keyword in domain.replace("-", "") for keyword in brand_keywords):
                official_domains = [extract_domain(item) for item in brand.official_domains]
                if domain not in official_domains:
                    return True
    return False


def analyze_email(raw_headers: str, body: str | None, brands: List[BrandProfile]) -> EmailAnalysisResult:
    """Executa análise consolidada de e-mail para uso no scoring."""
    spf_pass, dkim_pass, dmarc_pass, parsed = analyze_email_authentication(raw_headers)
    urls_found = find_urls_in_email(body, raw_headers)
    suspicious_link_detected = has_suspicious_links(urls_found, brands)

    details: Dict[str, str | bool | list[str]] = {
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "dmarc_pass": dmarc_pass,
        "urls_found": urls_found,
        "suspicious_link_detected": suspicious_link_detected,
        "authentication_results": parsed.get("authentication-results", ""),
    }

    logger.info(
        "Email analisado - SPF:%s DKIM:%s DMARC:%s links:%s suspicious:%s",
        spf_pass,
        dkim_pass,
        dmarc_pass,
        len(urls_found),
        suspicious_link_detected,
    )

    return EmailAnalysisResult(
        spf_pass=spf_pass,
        dkim_pass=dkim_pass,
        dmarc_pass=dmarc_pass,
        urls_found=urls_found,
        suspicious_link_detected=suspicious_link_detected,
        details=details,
    )
