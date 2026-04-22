"""Heurísticas de URL/domínio para detecção de phishing (Fase 1)."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional
from urllib.parse import urlparse

import dns.exception
import dns.resolver

from backend.models.brand import BrandProfile

logger = logging.getLogger(__name__)

URL_REGEX = re.compile(
    r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(:\d+)?(?:/[\w\-.~:/?#[\]@!$&'()*+,;=%]*)?",
    re.IGNORECASE,
)


@dataclass(slots=True)
class DomainCheckResult:
    domain: str
    dns_resolves: bool
    typosquatting_detected: bool
    suspected_brand: Optional[str]
    official_match: bool
    reason: str


def extract_domain(value: str) -> str:
    """Extrai domínio limpo a partir de URL/domínio cru."""
    if not value:
        return ""

    candidate = value.strip().lower()
    if not candidate.startswith(("http://", "https://")):
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    hostname = parsed.hostname or ""
    return hostname.removeprefix("www.")


def extract_urls(text: str) -> List[str]:
    """Extrai URLs encontradas em texto livre."""
    if not text:
        return []
    return [match.group(0) for match in URL_REGEX.finditer(text)]


def _dns_resolves_sync(domain: str) -> bool:
    """Verificação síncrona de resolução DNS (A/AAAA)."""
    if not domain:
        return False

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    try:
        resolver.resolve(domain, "A")
        return True
    except dns.exception.DNSException:
        try:
            resolver.resolve(domain, "AAAA")
            return True
        except dns.exception.DNSException:
            return False


async def dns_resolves(domain: str) -> bool:
    """Wrapper assíncrono para consulta DNS."""
    try:
        return await asyncio.to_thread(_dns_resolves_sync, domain)
    except Exception as exc:  # pragma: no cover
        logger.warning("Erro ao verificar DNS para %s: %s", domain, exc)
        return False


def _levenshtein_distance(first: str, second: str) -> int:
    """Calcula distância de Levenshtein com programação dinâmica."""
    if first == second:
        return 0
    if not first:
        return len(second)
    if not second:
        return len(first)

    previous_row = list(range(len(second) + 1))
    for i, char_a in enumerate(first, start=1):
        current_row = [i]
        for j, char_b in enumerate(second, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_typosquatting(domain: str, official_domains: Iterable[str], max_distance: int = 2) -> bool:
    """
    Detecta typosquatting comparando domínio de entrada com domínios oficiais.

    Regras usadas:
    - Distância de Levenshtein <= 2
    - Mesmo TLD final (ex.: .ao)
    """
    clean_domain = extract_domain(domain)
    if not clean_domain:
        return False

    for official in official_domains:
        clean_official = extract_domain(official)
        if not clean_official:
            continue

        if clean_domain == clean_official:
            continue

        input_tld = clean_domain.split(".")[-1]
        official_tld = clean_official.split(".")[-1]
        if input_tld != official_tld:
            continue

        distance = _levenshtein_distance(clean_domain, clean_official)
        if distance <= max_distance:
            return True
    return False


def find_brand_by_domain_or_keyword(domain: str, brands: List[BrandProfile]) -> Optional[BrandProfile]:
    """Identifica marca associada por keyword no domínio ou por igualdade oficial."""
    clean_domain = extract_domain(domain)
    for brand in brands:
        official_domains = [extract_domain(item) for item in brand.official_domains]
        if clean_domain in official_domains:
            return brand

        for keyword in brand.keywords:
            normalized = keyword.lower().strip()
            if normalized and normalized.replace(" ", "") in clean_domain.replace("-", ""):
                return brand
    return None


def is_official_domain_for_brand(domain: str, brand: BrandProfile) -> bool:
    """Valida se domínio informado pertence à lista oficial da marca."""
    clean_domain = extract_domain(domain)
    official_domains = [extract_domain(item) for item in brand.official_domains]
    return clean_domain in official_domains


async def evaluate_domain(domain_or_url: str, brands: List[BrandProfile]) -> DomainCheckResult:
    """Executa checagens de DNS, typosquatting e domínio oficial."""
    domain = extract_domain(domain_or_url)
    if not domain:
        return DomainCheckResult(
            domain="",
            dns_resolves=False,
            typosquatting_detected=False,
            suspected_brand=None,
            official_match=False,
            reason="Domínio inválido.",
        )

    dns_ok = await dns_resolves(domain)
    brand = find_brand_by_domain_or_keyword(domain, brands)

    if not dns_ok:
        return DomainCheckResult(
            domain=domain,
            dns_resolves=False,
            typosquatting_detected=False,
            suspected_brand=brand.name if brand else None,
            official_match=False,
            reason="Domínio não resolve DNS.",
        )

    if brand is None:
        return DomainCheckResult(
            domain=domain,
            dns_resolves=True,
            typosquatting_detected=False,
            suspected_brand=None,
            official_match=False,
            reason="Nenhuma marca monitorada detectada no domínio.",
        )

    official_domains = [extract_domain(item) for item in brand.official_domains]
    official_match = domain in official_domains
    typo = is_typosquatting(domain, official_domains)

    if official_match:
        reason = "Domínio oficial validado para a marca detectada."
    elif typo:
        reason = "Possível typosquatting detectado para marca monitorada."
    else:
        reason = "Marca detectada em domínio não oficial."

    return DomainCheckResult(
        domain=domain,
        dns_resolves=True,
        typosquatting_detected=typo,
        suspected_brand=brand.name,
        official_match=official_match,
        reason=reason,
    )
