"""Heurísticas de URL/domínio para detecção de phishing (versão melhorada)."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import dns.exception
import dns.resolver

try:
    import tldextract as _tldextract_mod
    _HAS_TLDEXTRACT = True
    def _tld_domain_body(d: str) -> str:
        return _tldextract_mod.extract(d).domain.lower()
except ImportError:
    _HAS_TLDEXTRACT = False
    def _tld_domain_body(d: str) -> str:
        return d.split(".")[0].lower()

# alias usado em find_brand_by_domain_or_keyword
import sys as _sys
_sys.modules[__name__].__dict__.setdefault("tldextract", None)
try:
    import tldextract
except ImportError:
    tldextract = None  # type: ignore

from backend.models.brand import BrandProfile

logger = logging.getLogger(__name__)

URL_REGEX = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)

# Resolver global (melhor performance)
resolver = dns.resolver.Resolver()
resolver.timeout = 2.0
resolver.lifetime = 2.0

# ─── Domínios institucionais angolanos — nunca sinalizados ────────
#
# PROBLEMA: "itel.gov.ao" contém "itel" → sistema confundia com "Unitel".
# Qualquer domínio .gov.ao ou nesta lista é considerado legítimo
# independentemente das keywords que contenha.

_INSTITUTIONAL_DOMAINS: set = {
    "itel.gov.ao", "inacom.gov.ao", "mintic.gov.ao", "minfin.gov.ao",
    "ine.gov.ao", "governo.ao", "presidencia.ao", "bna.ao",
    "mineduca.gov.ao", "minsa.gov.ao", "mirex.gov.ao", "tribunal.ao",
    "emis.ao", "multicaixa.ao", "angop.ao", "jornaldeangola.ao",
}

# Excepções: corpos de domínio que contêm uma keyword de marca
# mas pertencem a entidades completamente diferentes.
# Formato: brand_keyword → {domain_bodies_permitidos}
_KEYWORD_EXCEPTIONS: dict[str, set] = {
    "unitel":     {"itel"},
    "multicaixa": {"caixa", "caix"},
    "bai":        {"embai", "baia"},
    "movicel":    set(),
    "africell":   set(),
    "atlantico":  {"atlanticosul"},
}


def _is_institutional_domain(domain: str) -> bool:
    """True se o domínio é governamental/institucional angolano legítimo."""
    d = domain.lower().strip()
    if d in _INSTITUTIONAL_DOMAINS:
        return True
    for inst in _INSTITUTIONAL_DOMAINS:
        if d.endswith("." + inst):
            return True
    if d.endswith(".gov.ao") or d.endswith(".gov.ao."):
        return True
    return False


@dataclass(slots=True)
class DomainCheckResult:
    domain: str
    dns_resolves: bool
    typosquatting_detected: bool
    suspected_brand: Optional[str]
    official_match: bool
    reason: str


# ─── Extração ─────────────────────────────────────────────────────

def extract_domain(value: str) -> str:
    if not value:
        return ""

    candidate = value.strip().lower()
    if not candidate.startswith(("http://", "https://")):
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    hostname = parsed.hostname or ""

    return hostname.removeprefix("www.")


def extract_urls(text: str) -> List[str]:
    if not text:
        return []

    return list(set(match.group(0) for match in URL_REGEX.finditer(text)))


# ─── DNS ──────────────────────────────────────────────────────────

def _dns_resolves_sync(domain: str) -> Tuple[bool, str]:
    if not domain:
        return False, "empty"

    try:
        resolver.resolve(domain, "A")
        return True, "ok"

    except dns.resolver.NXDOMAIN:
        return False, "nxdomain"

    except dns.resolver.Timeout:
        return False, "timeout"

    except dns.exception.DNSException:
        try:
            resolver.resolve(domain, "AAAA")
            return True, "ok"
        except Exception:
            return False, "no_records"


async def dns_resolves(domain: str) -> Tuple[bool, str]:
    try:
        return await asyncio.to_thread(_dns_resolves_sync, domain)
    except Exception as exc:
        logger.warning("Erro DNS %s: %s", domain, exc)
        return False, "error"


# ─── Typosquatting ────────────────────────────────────────────────

def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0

    if not a:
        return len(b)

    if not b:
        return len(a)

    prev = list(range(len(b) + 1))

    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = prev[j] + 1
            dele = curr[j - 1] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, dele, sub))
        prev = curr

    return prev[-1]


def _strip_tld(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else domain


def is_typosquatting(domain: str, official_domains: Iterable[str], max_distance: int = 2) -> Optional[str]:
    """
    Detecta typosquatting com protecções contra falsos positivos:

      1. Domínios institucionais (.gov.ao, etc.) → nunca sinalizados
      2. Excepções de keyword (itel ≠ unitel, caixa ≠ multicaixa, etc.)
      3. Distância de Levenshtein apenas para domínios com TLD igual
      4. Para TLD diferente: o corpo do domínio suspeito tem de COMEÇAR
         com o corpo oficial (não apenas contê-lo) — regra mais estrita
    """
    if _is_institutional_domain(domain):
        return None

    clean_domain = extract_domain(domain)
    if not clean_domain:
        return None

    input_body = _strip_tld(clean_domain)

    # Corpo demasiado curto → falsos positivos fáceis
    if len(input_body) < 4:
        return None

    for official in official_domains:
        clean_official = extract_domain(official)
        if not clean_official or clean_domain == clean_official:
            continue

        official_body = _strip_tld(clean_official)

        # Verificar excepções: este corpo de domínio é uma entidade diferente?
        for brand_kw, exceptions in _KEYWORD_EXCEPTIONS.items():
            if brand_kw in official_body:
                if input_body in exceptions or any(exc in input_body for exc in exceptions if exc):
                    return None  # é uma excepção legítima, não phishing

        input_tld    = clean_domain.split(".")[-1]
        official_tld = clean_official.split(".")[-1]

        if input_tld == official_tld:
            # Mesmo TLD → distância de Levenshtein
            if _levenshtein_distance(clean_domain, clean_official) <= max_distance:
                return clean_official
        else:
            # TLD diferente → mais estrito: o corpo tem de COMEÇAR com o oficial
            # (evita "unitelmoney.net" ser marcado só por conter "unitel")
            # E o comprimento não pode ser muito maior (ratio ≤ 2x)
            if (
                official_body
                and input_body.startswith(official_body)
                and len(input_body) <= len(official_body) * 2
            ):
                return clean_official

    return None


# ─── Subdomain spoof ──────────────────────────────────────────────

def _is_subdomain_spoof(domain: str, official_domains: List[str]) -> bool:
    for official in official_domains:
        if official in domain and domain != official:
            return True
    return False


# ─── Marca ────────────────────────────────────────────────────────

def find_brand_by_domain_or_keyword(domain: str, brands: List[BrandProfile]) -> Optional[BrandProfile]:
    """
    Encontra a marca associada a um domínio.

    Protecção: domínios institucionais não são associados a marcas privadas,
    mesmo que contenham a keyword da marca no nome.
    (ex: itel.gov.ao contém "itel" mas não é da Unitel)
    """
    clean_domain = extract_domain(domain)

    # Domínios institucionais não imitam marcas
    if _is_institutional_domain(clean_domain):
        return None

    for brand in brands:
        official_domains = [extract_domain(d) for d in brand.official_domains]

        if clean_domain in official_domains:
            return brand

        domain_clean = clean_domain.replace("-", "")

        for keyword in brand.keywords:
            normalized = keyword.lower().strip().replace(" ", "")

            if normalized and len(normalized) >= 4:
                # Verificar excepção: este domínio é uma entidade diferente que usa a mesma keyword?
                exceptions = _KEYWORD_EXCEPTIONS.get(normalized, set())
                domain_body = tldextract.extract(clean_domain).domain.lower() if _HAS_TLDEXTRACT else domain_clean
                if domain_body in exceptions or any(exc in domain_body for exc in exceptions if exc):
                    continue

                if normalized in domain_clean:
                    return brand

    return None


# ─── Pipeline principal ───────────────────────────────────────────

async def evaluate_domain(domain_or_url: str, brands: List[BrandProfile]) -> DomainCheckResult:
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

    # Marca
    brand = find_brand_by_domain_or_keyword(domain, brands)
    official_domains = [extract_domain(d) for d in brand.official_domains] if brand else []
    official_match = domain in official_domains

    # Subdomain spoof
    subdomain_attack = False
    spoof_brand = None

    if not official_match:
        for b in brands:
            offs = [extract_domain(d) for d in b.official_domains]
            if _is_subdomain_spoof(domain, offs):
                subdomain_attack = True
                spoof_brand = b
                break

    # Typosquatting
    typo = False
    typo_brand = None
    matched_domain = None

    if not official_match and not subdomain_attack:
        for b in brands:
            result = is_typosquatting(domain, b.official_domains)
            if result:
                typo = True
                typo_brand = b
                matched_domain = result
                break

    suspected = brand or typo_brand or spoof_brand

    # DNS
    dns_ok, dns_reason = await dns_resolves(domain)

    # Decisão final
    if official_match:
        reason = "Domínio oficial validado."
    elif subdomain_attack:
        reason = f"Subdomínio malicioso detectado (spoof de {spoof_brand.name})."
    elif typo:
        reason = f"Typosquatting detectado (imitando {matched_domain})."
    elif not dns_ok:
        reason = f"Domínio não resolve DNS ({dns_reason})."
    elif brand is not None:
        reason = "Marca detectada em domínio não oficial."
    else:
        reason = "Domínio aparentemente neutro."

    return DomainCheckResult(
        domain=domain,
        dns_resolves=dns_ok,
        typosquatting_detected=typo,
        suspected_brand=suspected.name if suspected else None,
        official_match=official_match,
        reason=reason,
    )
