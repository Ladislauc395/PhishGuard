import time
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from bs4 import BeautifulSoup

from schemas import (
    CrawlRequest,
    CrawlResponse,
    HealthResponse,
    BrandVerdict,
    OfficialDomainCandidate,
)
from browser import browser_manager, PageCrawler
from utils import (
    detect_login_form,
    extract_metadata,
    analyze_security,
    analyze_clone_indicators,
    build_redirect_info,
    encode_screenshot,
    safe_get_text,
)
from brand_resolver import resolve_brand, BrandVerdict as BrandVerdictDC

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("crawler.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Crawler Service iniciando...")
    await browser_manager.start()
    yield
    logger.info("🛑 Crawler Service encerrando...")
    await browser_manager.stop()


app = FastAPI(
    title="Crawler Service",
    description=(
        "Serviço de crawling com Playwright. "
        "Detecta login forms, captura HTML, rastreia redirects, "
        "e resolve dinamicamente o domínio oficial de qualquer marca via busca na web."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _convert_verdict(dc: BrandVerdictDC) -> BrandVerdict:
    return BrandVerdict(
        brand_name=dc.brand_name,
        official_domain=dc.official_domain,
        current_domain=dc.current_domain,
        is_official=dc.is_official,
        is_impersonation=dc.is_impersonation,
        confidence=dc.confidence,
        impersonation_risk=dc.impersonation_risk,
        search_results_used=dc.search_results_used,
        explanation=dc.explanation,
        official_candidates=[
            OfficialDomainCandidate(
                domain=c.domain,
                score=c.score,
                occurrences=c.occurrences,
                source_urls=c.source_urls,
            )
            for c in dc.official_candidates
        ],
    )


@app.get("/health", response_model=HealthResponse, tags=["Status"])
async def health():
    return HealthResponse(
        status="ok" if browser_manager.is_ready else "degraded",
        playwright_ready=browser_manager.is_ready,
    )


@app.post("/crawl", response_model=CrawlResponse, tags=["Crawler"])
async def crawl(req: CrawlRequest):
    """
    Crawlea uma URL com Playwright e executa análise completa.

    **Detecção dinâmica de marca (v2):**
    1. Extrai a marca da página (og:site_name, title, logo alt, copyright…)
    2. Busca o domínio oficial no DuckDuckGo/Bing
    3. Ranqueia candidatos por score de confiança
    4. Emite veredito com risco de impersonação

    Exemplo: `bantubet-clone.xyz` → detecta "BantuBet" → busca → oficial: `bantubet.com` → IMPERSONAÇÃO
    """
    start_ts = time.monotonic()
    warnings: list[str] = []
    original_url = req.url

    try:
        async with browser_manager.new_context() as context:
            crawler = PageCrawler(context)

            try:
                page, redirect_chain, screenshot_bytes, http_status = await crawler.crawl(
                    url=original_url,
                    timeout=req.timeout,
                    wait_for=req.wait_for,
                    take_screenshot=req.screenshot,
                )
            except TimeoutError as e:
                raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=str(e))
            except RuntimeError as e:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))

            final_url = page.url
            html = await page.content()
            soup = BeautifulSoup(html, "lxml")

            login_form       = detect_login_form(html, final_url)
            metadata         = extract_metadata(html, final_url)
            security         = analyze_security(html, final_url)
            clone_indicators = analyze_clone_indicators(html, final_url)
            redirect_info    = build_redirect_info(original_url, final_url, redirect_chain)
            text_content     = safe_get_text(soup)

            # Análise dinâmica de marca via busca na web
            brand_verdict_dc = await resolve_brand(html, final_url)
            brand_verdict    = _convert_verdict(brand_verdict_dc)

            if redirect_info.cross_domain:
                warnings.append(f"Redirecionamento cross-domain: {original_url} → {final_url}")
            if brand_verdict.is_impersonation:
                warnings.append(
                    f"POSSÍVEL IMPERSONAÇÃO: '{brand_verdict.brand_name}' "
                    f"(oficial: {brand_verdict.official_domain} | "
                    f"risco: {brand_verdict.impersonation_risk:.0%})"
                )
            if not brand_verdict.is_official and brand_verdict.impersonation_risk >= 0.5:
                warnings.append(brand_verdict.explanation)
            if security.has_obfuscated_js:
                warnings.append("JavaScript potencialmente ofuscado detectado.")
            if clone_indicators.suspicious_tld:
                warnings.append("TLD suspeito associado a domínios fraudulentos.")
            if login_form.suspicious_indicators:
                warnings.append(f"Indicadores suspeitos: {', '.join(login_form.suspicious_indicators)}")

            duration_ms = int((time.monotonic() - start_ts) * 1000)
            logger.info(
                f"✓ {final_url} | brand={brand_verdict.brand_name!r} | "
                f"official={brand_verdict.is_official} | risk={brand_verdict.impersonation_risk:.2f} | "
                f"{duration_ms}ms"
            )

            return CrawlResponse(
                success=True,
                url=final_url,
                status_code=http_status,
                html=html,
                html_length=len(html),
                text_content=text_content,
                metadata=metadata,
                login_form=login_form,
                redirect=redirect_info,
                security=security,
                clone_indicators=clone_indicators,
                brand_verdict=brand_verdict,
                screenshot_base64=encode_screenshot(screenshot_bytes) if screenshot_bytes else None,
                crawl_duration_ms=duration_ms,
                warnings=warnings,
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Erro inesperado ao crawlear {original_url}")
        duration_ms = int((time.monotonic() - start_ts) * 1000)
        return CrawlResponse(
            success=False,
            url=original_url,
            redirect=build_redirect_info(original_url, original_url, [original_url]),
            crawl_duration_ms=duration_ms,
            error=str(e),
            warnings=warnings,
        )


@app.post("/crawl/batch", response_model=list[CrawlResponse], tags=["Crawler"])
async def crawl_batch(requests: list[CrawlRequest]):
    """Crawlea múltiplas URLs em sequência. Máximo 10 por chamada."""
    if len(requests) > 10:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Máximo de 10 URLs por batch.",
        )
    results = []
    for req in requests:
        result = await crawl(req)
        results.append(result)
    return results


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=9000, reload=False, log_level="info")
    