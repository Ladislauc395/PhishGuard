"""
backend/services/brand_search.py
──────────────────────────────────
Validação dinâmica de marcas via Google Custom Search API.

Propósito:
  Quando um domínio suspeito menciona uma marca que NÃO está no KNOWN_BRANDS
  estático, este módulo pesquisa o domínio oficial dessa marca no Google
  e compara com o domínio em análise para detetar spoofing dinâmico.

Fluxo:
  1. Extrair palavra-chave de marca do domínio suspeito
  2. Pesquisar "marca site oficial" no Google Custom Search
  3. Extrair domínio oficial a partir dos resultados
  4. Comparar com o domínio em análise
  5. Devolver veredicto + domínio oficial encontrado

Limite gratuito: 100 pesquisas/dia
Chamada apenas quando: domínio não está em KNOWN_BRANDS E há suspeita real

Variáveis no .env:
    GOOGLE_CUSTOM_SEARCH_API_KEY
    GOOGLE_CUSTOM_SEARCH_ENGINE_ID   (CX — Programmable Search Engine ID)

Docs: https://developers.google.com/custom-search/v1/overview
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import List, Optional
from urllib.parse import urlparse

import requests
import tldextract

logger = logging.getLogger(__name__)

CUSTOM_SEARCH_API_KEY = os.getenv("GOOGLE_CUSTOM_SEARCH_API_KEY", "")
CUSTOM_SEARCH_CX      = os.getenv("GOOGLE_CUSTOM_SEARCH_ENGINE_ID", "")

CUSTOM_SEARCH_URL = "https://www.googleapis.com/customsearch/v1"
REQUEST_TIMEOUT   = 8

# Número máximo de resultados a analisar por pesquisa (máx. 10 na API)
MAX_RESULTS = 5

# Score mínimo de similaridade para considerar que o domínio imita a marca
SIMILARITY_THRESHOLD = 0.70

# TLDs comuns para filtrar resultados da pesquisa
COMMON_TLDS = {".com", ".org", ".net", ".ao", ".pt", ".br", ".co", ".io", ".gov"}

# Domínios de agregadores/wikis que não são domínios oficiais de marcas
AGGREGATOR_DOMAINS = {
    "wikipedia.org", "linkedin.com", "facebook.com", "twitter.com",
    "instagram.com", "youtube.com", "crunchbase.com", "bloomberg.com",
    "reuters.com", "forbes.com", "trustpilot.com", "glassdoor.com",
    "indeed.com", "appstore.com", "play.google.com", "apps.apple.com",
}


@dataclass
class BrandSearchResult:
    brand_keyword: str
    official_domain: Optional[str]       = None
    official_url: Optional[str]          = None
    confidence: float                    = 0.0   # 0.0 – 1.0
    is_spoof: bool                       = False
    similarity_score: float              = 0.0
    search_performed: bool               = False
    error: Optional[str]                 = None
    all_candidates: List[str]            = field(default_factory=list)


# ─── Helpers ──────────────────────────────────────────────────────

def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower().strip())


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _extract_root_domain(url: str) -> Optional[str]:
    """Extrai domínio raiz limpo de uma URL."""
    try:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return None


def _is_aggregator(domain: str) -> bool:
    """Verifica se o domínio é um agregador/rede social (não é o site oficial da marca)."""
    return any(agg in domain for agg in AGGREGATOR_DOMAINS)


def _extract_brand_keyword(domain: str) -> Optional[str]:
    """
    Extrai a palavra-chave de marca de um domínio suspeito.

    Exemplos:
      paypal-angola.com    → "paypal"
      dhl-entrega.ao       → "dhl"
      mtn-money-verify.net → "mtn"
      banco-atlantico.info → "banco atlantico"
    """
    ext = tldextract.extract(domain)
    if not ext.domain:
        return None

    # Remove separadores e sufixos comuns de phishing
    parts = re.split(r"[-_.]", ext.domain.lower())
    noise = {
        "www", "mail", "secure", "login", "account", "verify", "update",
        "portal", "online", "mobile", "app", "web", "net", "info",
        "angola", "ao", "pt", "br", "africa", "express", "money",
        "pay", "bank", "official", "support", "help", "service",
        "entrega", "tracking", "confirm", "validation",
    }

    keywords = [p for p in parts if p and p not in noise and len(p) >= 3]

    if not keywords:
        return None

    # Devolve as primeiras 2 palavras significativas como keyword de pesquisa
    return " ".join(keywords[:2])


# ─── Custom Search API ────────────────────────────────────────────

def _search_official_domain(brand_keyword: str) -> List[str]:
    """
    Pesquisa o domínio oficial de uma marca no Google Custom Search.

    Returns:
        Lista de domínios candidatos a oficial (ordenados por relevância)
    """
    if not CUSTOM_SEARCH_API_KEY or not CUSTOM_SEARCH_CX:
        raise ValueError("GOOGLE_CUSTOM_SEARCH_API_KEY ou GOOGLE_CUSTOM_SEARCH_ENGINE_ID não configurado")

    # Query otimizada para encontrar o site oficial
    query = f"{brand_keyword} site oficial"

    try:
        resp = requests.get(
            CUSTOM_SEARCH_URL,
            params={
                "key": CUSTOM_SEARCH_API_KEY,
                "cx":  CUSTOM_SEARCH_CX,
                "q":   query,
                "num": MAX_RESULTS,
                "lr":  "lang_pt",  # preferência por resultados em português
            },
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data  = resp.json()
        items = data.get("items", [])

        candidates: List[str] = []

        for item in items:
            url    = item.get("link", "")
            domain = _extract_root_domain(url)

            if not domain:
                continue

            # Ignorar agregadores — não são sites oficiais
            if _is_aggregator(domain):
                continue

            # O domínio candidato deve conter parte da keyword pesquisada
            keyword_norm = _normalize(brand_keyword)
            domain_norm  = _normalize(domain)

            if keyword_norm in domain_norm or _similarity(keyword_norm, domain_norm.split(".")[0]) >= 0.6:
                if domain not in candidates:
                    candidates.append(domain)

        logger.info(
            "Custom Search '%s' → %d candidatos: %s",
            query, len(candidates), candidates
        )
        return candidates

    except requests.exceptions.RequestException as exc:
        logger.error("Custom Search API erro: %s", exc)
        raise


# ─── Verificação de spoof ─────────────────────────────────────────

def _check_spoof_against_official(
    suspect_domain: str,
    official_domain: str,
) -> tuple[bool, float]:
    """
    Verifica se o domínio suspeito imita o domínio oficial.

    Casos detectados:
      - paypal-angola.com vs paypal.com → typosquatting/variante
      - paypal.ao.phishing.net vs paypal.ao → subdomain spoof
      - pay-pal.com vs paypal.com → separador suspeito
      - paypai.com vs paypal.com → troca de caracteres

    Returns:
        (is_spoof, similarity_score)
    """
    suspect_norm  = _normalize(suspect_domain.split(".")[0])  # só o corpo
    official_norm = _normalize(official_domain.split(".")[0])

    # Domínio idêntico → não é spoof
    if suspect_domain == official_domain:
        return False, 1.0

    sim = _similarity(suspect_norm, official_norm)

    # Subdomain spoof: oficial aparece dentro do suspeito
    if official_domain in suspect_domain and suspect_domain != official_domain:
        return True, 0.95

    # Alta similaridade com TLD diferente ou variante
    if sim >= SIMILARITY_THRESHOLD and suspect_domain != official_domain:
        return True, sim

    return False, sim


# ─── Função principal ─────────────────────────────────────────────

def validate_brand_dynamic(
    suspect_domain: str,
    force_search: bool = False,
) -> BrandSearchResult:
    """
    Valida dinamicamente se um domínio imita uma marca desconhecida.

    Deve ser chamada APENAS quando o domínio não está no KNOWN_BRANDS
    e há suspeita real (keyword de marca detetada no domínio).

    Args:
        suspect_domain: domínio a analisar (ex: "paypal-angola.com")
        force_search:   forçar pesquisa mesmo sem keyword óbvia

    Returns:
        BrandSearchResult com veredicto e domínio oficial encontrado
    """
    # Extrair keyword de marca do domínio suspeito
    brand_keyword = _extract_brand_keyword(suspect_domain)

    if not brand_keyword and not force_search:
        return BrandSearchResult(
            brand_keyword="",
            error="Nenhuma keyword de marca identificada no domínio",
        )

    result = BrandSearchResult(
        brand_keyword=brand_keyword or suspect_domain,
        search_performed=True,
    )

    if not CUSTOM_SEARCH_API_KEY or not CUSTOM_SEARCH_CX:
        result.error = "Custom Search API não configurada (GOOGLE_CUSTOM_SEARCH_API_KEY / GOOGLE_CUSTOM_SEARCH_ENGINE_ID)"
        return result

    try:
        candidates = _search_official_domain(brand_keyword or suspect_domain)
        result.all_candidates = candidates

        if not candidates:
            result.error = "Nenhum domínio oficial encontrado para a marca"
            return result

        # Testar spoof contra cada candidato (mais relevante primeiro)
        best_sim    = 0.0
        best_domain = None

        for candidate in candidates:
            is_spoof, sim = _check_spoof_against_official(suspect_domain, candidate)

            if sim > best_sim:
                best_sim    = sim
                best_domain = candidate

            if is_spoof:
                result.official_domain  = candidate
                result.official_url     = f"https://{candidate}"
                result.is_spoof         = True
                result.similarity_score = sim
                result.confidence       = sim

                logger.warning(
                    "Spoof dinâmico detetado: '%s' imita '%s' (sim=%.2f)",
                    suspect_domain, candidate, sim,
                )
                return result

        # Sem spoof confirmado — regista o candidato mais relevante
        result.official_domain  = best_domain
        result.official_url     = f"https://{best_domain}" if best_domain else None
        result.similarity_score = best_sim
        result.confidence       = best_sim
        result.is_spoof         = False

    except ValueError as exc:
        result.error           = str(exc)
        result.search_performed = False

    except Exception as exc:
        logger.error("Erro inesperado no brand_search: %s", exc)
        result.error = f"Erro interno: {exc}"

    return result


# ─── Integração com url_analyzer ──────────────────────────────────

def check_dynamic_brand_spoof(
    domain: str,
    known_brands: dict,
    score: int,
    reasons: list,
) -> tuple[int, list]:
    """
    Wrapper para integração direta no pipeline do url_analyzer.

    Só executa a pesquisa se:
      1. O domínio não está nos KNOWN_BRANDS estáticos
      2. O domínio tem uma keyword de marca identificável
      3. A Custom Search API está configurada

    Args:
        domain:       domínio a analisar
        known_brands: dict KNOWN_BRANDS do url_analyzer
        score:        score acumulado atual
        reasons:      lista de razões atual

    Returns:
        (score, reasons) atualizados
    """
    # Verificar se já está nos KNOWN_BRANDS (não duplicar verificação)
    import tldextract as _tld

    domain_body = _tld.extract(domain).domain.lower()

    for brand_domains in known_brands.values():
        for official in brand_domains:
            if domain.endswith(official) or official in domain:
                return score, reasons  # já coberto pelo KNOWN_BRANDS

    # Só pesquisa se a API estiver configurada
    if not CUSTOM_SEARCH_API_KEY or not CUSTOM_SEARCH_CX:
        return score, reasons

    # Só pesquisa se houver keyword de marca identificável
    keyword = _extract_brand_keyword(domain)
    if not keyword:
        return score, reasons

    try:
        result = validate_brand_dynamic(domain)

        if result.is_spoof and result.official_domain:
            score += 75
            reasons.append(
                f"dynamic_brand_spoof:{result.brand_keyword}"
                f"→official:{result.official_domain}"
                f"(sim={result.similarity_score:.2f})"
            )
            logger.warning(
                "Spoof dinâmico: '%s' imita '%s'",
                domain, result.official_domain,
            )

        elif result.error:
            logger.debug("Brand search inconclusivo para '%s': %s", domain, result.error)

    except Exception as exc:
        logger.debug("Brand search falhou para '%s': %s", domain, exc)

    return score, reasons
