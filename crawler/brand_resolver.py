"""
brand_resolver.py
─────────────────
Detecção dinâmica de marca + resolução do domínio oficial via busca na web.

Fluxo:
  1. Extrair "marca provável" da página (título, OG, meta, logo alt, copyright)
  2. Buscar no DuckDuckGo: "<marca> official website"
  3. Parsear os top resultados e extrair domínios candidatos
  4. Rankear por frequência + heurísticas (HTTPS, sem subdomínio suspeito, TLD confiável)
  5. Retornar domínio oficial com score de confiança
  6. Comparar com o domínio atual → gerar BrandVerdict
"""

import re
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, quote_plus

import httpx
import tldextract
from bs4 import BeautifulSoup

logger = logging.getLogger("crawler.brand_resolver")

# ─── Config ───────────────────────────────────────────────────────

SEARCH_TIMEOUT = 10.0
MAX_SEARCH_RESULTS = 8
MIN_BRAND_LENGTH = 3

TRUSTED_TLDS = {
    "com", "com.br", "org", "net", "io", "co", "app",
    "gov", "gov.br", "edu", "edu.br", "co.uk", "de", "fr",
}

SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "top",
    "click", "link", "live", "online", "site", "fun",
    "vip", "club", "icu", "monster", "cyou",
}

NOISE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "wikipedia.org",
    "reddit.com", "twitter.com", "instagram.com", "tiktok.com",
    "linkedin.com", "pinterest.com", "amazon.com", "bing.com",
    "duckduckgo.com", "yahoo.com", "trustpilot.com", "glassdoor.com",
    "indeed.com", "bloomberg.com", "reuters.com", "forbes.com",
    "g2.com", "capterra.com", "play.google.com", "apps.apple.com",
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ─── Data classes ─────────────────────────────────────────────────

@dataclass
class BrandCandidate:
    name: str
    confidence: float  # 0.0–1.0


@dataclass
class OfficialDomainCandidate:
    domain: str
    score: float
    occurrences: int
    source_urls: list[str] = field(default_factory=list)


@dataclass
class BrandVerdict:
    """Resultado final da análise de autenticidade do domínio."""
    brand_name: Optional[str]            # Marca detectada na página
    official_domain: Optional[str]       # Domínio oficial encontrado
    current_domain: str                  # Domínio sendo analisado
    is_official: bool                    # É o site oficial?
    is_impersonation: bool               # Está se passando pela marca?
    confidence: float                    # Confiança da análise (0.0–1.0)
    impersonation_risk: float            # Risco de impersonação (0.0–1.0)
    search_results_used: int
    explanation: str
    official_candidates: list[OfficialDomainCandidate] = field(default_factory=list)


# ─── Brand Extraction ─────────────────────────────────────────────

_COPYRIGHT_RE = re.compile(
    r"©\s*(?:\d{4}[\s\-–]+)?\s*([A-Za-zÀ-ÿ0-9\s&'.\-]{2,40})",
    re.IGNORECASE,
)

_BRANDNAME_CLEAN_RE = re.compile(r"\b(ltd|llc|inc|s\.a|sa|ltda|me|eireli|corp|group|holding)\b", re.I)


def extract_brand_from_page(html: str, url: str) -> Optional[BrandCandidate]:
    """
    Extrai a marca mais provável da página usando múltiplos sinais.
    Retorna None se não encontrar nada confiável.
    """
    soup = BeautifulSoup(html, "lxml")
    candidates: dict[str, float] = {}

    def add(name: str, weight: float):
        name = _clean_brand(name)
        if name and len(name) >= MIN_BRAND_LENGTH:
            candidates[name] = candidates.get(name, 0.0) + weight

    # 1. OG site_name (sinal mais confiável)
    og_site = soup.find("meta", property="og:site_name")
    if og_site and og_site.get("content"):
        add(og_site["content"], 1.0)

    # 2. OG title (pegar parte antes de " | " ou " - ")
    og_title = soup.find("meta", property="og:title")
    if og_title and og_title.get("content"):
        part = re.split(r"[|\-–]", og_title["content"])[0]
        add(part, 0.5)

    # 3. <title> (parte após separador — geralmente o nome do site)
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
        parts = re.split(r"[|\-–]", title)
        # Última parte geralmente é o nome do site
        if len(parts) > 1:
            add(parts[-1], 0.7)
        add(parts[0], 0.3)

    # 4. Logo alt text
    for img in soup.find_all("img", alt=True):
        alt = img.get("alt", "")
        src = img.get("src", "").lower()
        if "logo" in src or "logo" in alt.lower():
            add(alt, 0.6)

    # 5. Copyright no footer
    footer = soup.find("footer") or soup
    footer_text = footer.get_text(" ", strip=True)
    for m in _COPYRIGHT_RE.finditer(footer_text):
        add(m.group(1), 0.8)

    # 6. apple-mobile-web-app-title
    apple_meta = soup.find("meta", attrs={"name": "apple-mobile-web-app-title"})
    if apple_meta and apple_meta.get("content"):
        add(apple_meta["content"], 0.9)

    # 7. application-name
    app_name = soup.find("meta", attrs={"name": "application-name"})
    if app_name and app_name.get("content"):
        add(app_name["content"], 0.9)

    # 8. Fallback: domínio atual sem TLD
    ext = tldextract.extract(url)
    if ext.domain:
        add(ext.domain.replace("-", " ").replace("_", " "), 0.2)

    if not candidates:
        return None

    best = max(candidates, key=candidates.__getitem__)
    score = min(candidates[best] / 2.0, 1.0)  # normaliza

    return BrandCandidate(name=best, confidence=score)


def _clean_brand(name: str) -> str:
    name = name.strip()
    # Remove sufixos legais
    name = _BRANDNAME_CLEAN_RE.sub("", name).strip(" .,")
    # Remove URLs acidentais
    if "http" in name.lower() or len(name) > 60:
        return ""
    # Normaliza espaços
    name = re.sub(r"\s+", " ", name)
    return name


# ─── Web Search ───────────────────────────────────────────────────

async def _search_duckduckgo(query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[str]:
    """Busca no DuckDuckGo HTML e retorna lista de URLs dos resultados."""
    encoded = quote_plus(query)
    url = f"https://html.duckduckgo.com/html/?q={encoded}"

    try:
        async with httpx.AsyncClient(
            headers=HEADERS,
            timeout=SEARCH_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "lxml")
        urls = []

        # DuckDuckGo HTML usa <a class="result__a">
        for a in soup.find_all("a", class_="result__a", href=True):
            href = a["href"]
            # DuckDuckGo redireciona via //duckduckgo.com/l/?uddg=...
            if "uddg=" in href:
                import urllib.parse
                params = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
                if "uddg" in params:
                    href = urllib.parse.unquote(params["uddg"][0])
            if href.startswith("http"):
                urls.append(href)
            if len(urls) >= max_results:
                break

        return urls

    except Exception as e:
        logger.warning(f"DuckDuckGo search falhou: {e}")
        return []


async def _search_bing_fallback(query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[str]:
    """Fallback: busca no Bing se DuckDuckGo falhar."""
    encoded = quote_plus(query)
    url = f"https://www.bing.com/search?q={encoded}"

    try:
        async with httpx.AsyncClient(
            headers=HEADERS,
            timeout=SEARCH_TIMEOUT,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "lxml")
        urls = []

        for li in soup.select("li.b_algo h2 a[href]"):
            href = li.get("href", "")
            if href.startswith("http"):
                urls.append(href)
            if len(urls) >= max_results:
                break

        return urls

    except Exception as e:
        logger.warning(f"Bing fallback falhou: {e}")
        return []


async def search_official_domain(brand_name: str) -> list[str]:
    """
    Busca '<brand> official website' e retorna URLs encontradas.
    Tenta DuckDuckGo primeiro, Bing como fallback.
    """
    query = f"{brand_name} official website"
    logger.info(f"🔍 Buscando domínio oficial para: '{brand_name}'")

    results = await _search_duckduckgo(query)
    if not results:
        results = await _search_bing_fallback(query)

    # Segunda busca mais específica se poucos resultados
    if len(results) < 3:
        query2 = f'"{brand_name}" site oficial'
        extra = await _search_duckduckgo(query2)
        results += extra

    return results[:MAX_SEARCH_RESULTS * 2]


# ─── Domain Ranking ───────────────────────────────────────────────

def _score_domain(domain: str, brand_name: str) -> float:
    """Pontua um domínio candidato como 'oficial'."""
    ext = tldextract.extract(domain)
    registered = ext.registered_domain.lower()
    tld = ext.suffix.lower()
    dom = ext.domain.lower()
    brand_clean = brand_name.lower().replace(" ", "").replace("-", "")

    score = 0.0

    # TLD confiável
    if tld in TRUSTED_TLDS:
        score += 0.3
    if tld in SUSPICIOUS_TLDS:
        score -= 0.5

    # Nome do domínio contém a marca
    brand_words = brand_name.lower().split()
    if any(w in dom for w in brand_words if len(w) > 2):
        score += 0.5
    if brand_clean in dom.replace("-", "").replace("_", ""):
        score += 0.3

    # HTTPS implícito (se chegou aqui via busca, provavelmente é HTTPS)
    if domain.startswith("https"):
        score += 0.1

    # Sem subdomínio suspeito
    sub = ext.subdomain.lower()
    if sub in ("", "www"):
        score += 0.1
    elif sub in ("login", "secure", "account", "verify"):
        score -= 0.3  # suspeito

    # Domínio muito longo → suspeito
    if len(dom) > 20:
        score -= 0.2

    # Contém hífens em excesso → typosquat
    if dom.count("-") > 2:
        score -= 0.2

    return max(0.0, min(score, 1.0))


def rank_official_candidates(
    urls: list[str],
    brand_name: str,
) -> list[OfficialDomainCandidate]:
    """
    Agrega e ranqueia domínios encontrados nos resultados de busca.
    """
    domain_data: dict[str, OfficialDomainCandidate] = {}

    for url in urls:
        ext = tldextract.extract(url)
        if not ext.domain or not ext.suffix:
            continue

        registered = f"{ext.domain}.{ext.suffix}".lower()

        # Ignora domínios de ruído (buscadores, redes sociais, etc.)
        if registered in NOISE_DOMAINS:
            continue
        if ext.suffix in SUSPICIOUS_TLDS:
            continue

        if registered not in domain_data:
            score = _score_domain(url, brand_name)
            domain_data[registered] = OfficialDomainCandidate(
                domain=registered,
                score=score,
                occurrences=0,
                source_urls=[],
            )

        domain_data[registered].occurrences += 1
        domain_data[registered].source_urls.append(url)

    # Boost por frequência (aparecer várias vezes nos resultados = mais confiável)
    for candidate in domain_data.values():
        freq_bonus = min(candidate.occurrences * 0.1, 0.3)
        candidate.score = min(candidate.score + freq_bonus, 1.0)

    ranked = sorted(domain_data.values(), key=lambda c: c.score, reverse=True)
    return ranked[:5]


# ─── Verdict ──────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def build_verdict(
    current_url: str,
    brand: Optional[BrandCandidate],
    candidates: list[OfficialDomainCandidate],
    search_count: int,
) -> BrandVerdict:
    """
    Cruza o domínio atual com os candidatos oficiais e emite o veredito.
    """
    ext = tldextract.extract(current_url)
    current_domain = f"{ext.domain}.{ext.suffix}".lower()
    current_registered = ext.registered_domain.lower()

    if not brand or not candidates:
        return BrandVerdict(
            brand_name=brand.name if brand else None,
            official_domain=None,
            current_domain=current_domain,
            is_official=False,
            is_impersonation=False,
            confidence=0.1,
            impersonation_risk=0.0,
            search_results_used=search_count,
            explanation="Não foi possível determinar a marca ou o domínio oficial.",
            official_candidates=candidates,
        )

    top = candidates[0]
    official_domain = top.domain
    brand_name = brand.name

    # Correspondência exata
    is_official = current_registered == official_domain

    # Risco de impersonação
    impersonation_risk = 0.0
    explanation_parts = []

    if is_official:
        explanation_parts.append(f"✅ '{current_domain}' é o domínio oficial de '{brand_name}'.")
        confidence = min(top.score + 0.2, 1.0)
    else:
        explanation_parts.append(
            f"⚠️ '{current_domain}' não é o domínio oficial de '{brand_name}' "
            f"(oficial: '{official_domain}')."
        )

        # Levenshtein entre domínios (sem TLD)
        lev = _levenshtein(ext.domain, tldextract.extract(official_domain).domain)

        if lev <= 1:
            impersonation_risk = 0.95
            explanation_parts.append("Domínio quase idêntico ao oficial (possível typosquat crítico).")
        elif lev <= 3:
            impersonation_risk = 0.75
            explanation_parts.append(f"Domínio muito similar ao oficial (distância Levenshtein: {lev}).")
        elif ext.suffix in SUSPICIOUS_TLDS:
            impersonation_risk = 0.6
            explanation_parts.append("TLD suspeito associado a domínios fraudulentos.")

        # Marca no domínio atual mas não é o oficial
        brand_clean = brand_name.lower().replace(" ", "")
        if brand_clean in current_domain.replace("-", "").replace(".", ""):
            impersonation_risk = max(impersonation_risk, 0.7)
            explanation_parts.append("Nome da marca presente no domínio suspeito.")

        confidence = top.score * brand.confidence

    return BrandVerdict(
        brand_name=brand_name,
        official_domain=official_domain,
        current_domain=current_domain,
        is_official=is_official,
        is_impersonation=not is_official and impersonation_risk >= 0.5,
        confidence=round(confidence, 3),
        impersonation_risk=round(impersonation_risk, 3),
        search_results_used=search_count,
        explanation=" ".join(explanation_parts),
        official_candidates=candidates,
    )


# ─── Main Entry Point ─────────────────────────────────────────────

async def resolve_brand(html: str, url: str) -> BrandVerdict:
    """
    Pipeline completo:
      html + url → BrandVerdict

    Passos:
      1. Extrai marca da página
      2. Busca domínio oficial na web
      3. Ranqueia candidatos
      4. Emite veredito
    """
    brand = extract_brand_from_page(html, url)

    if not brand or brand.confidence < 0.1:
        ext = tldextract.extract(url)
        current = f"{ext.domain}.{ext.suffix}"
        logger.info(f"Marca não detectada para {url}")
        return BrandVerdict(
            brand_name=None,
            official_domain=None,
            current_domain=current,
            is_official=False,
            is_impersonation=False,
            confidence=0.0,
            impersonation_risk=0.0,
            search_results_used=0,
            explanation="Nenhuma marca identificável encontrada na página.",
        )

    logger.info(f"🏷️  Marca detectada: '{brand.name}' (confiança: {brand.confidence:.2f})")

    raw_urls = await search_official_domain(brand.name)
    candidates = rank_official_candidates(raw_urls, brand.name)

    verdict = build_verdict(
        current_url=url,
        brand=brand,
        candidates=candidates,
        search_count=len(raw_urls),
    )

    logger.info(
        f"{'✅ Oficial' if verdict.is_official else '🚨 Suspeito'} | "
        f"Marca: {verdict.brand_name} | "
        f"Oficial: {verdict.official_domain} | "
        f"Atual: {verdict.current_domain} | "
        f"Risco: {verdict.impersonation_risk:.2f}"
    )

    return verdict
