import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional, List, Tuple

from playwright.async_api import (
    async_playwright,
    Browser,
    BrowserContext,
    Page,
    Response,
    PlaywrightContextManager,
    Error as PlaywrightError,
    TimeoutError as PlaywrightTimeoutError,
)

logger = logging.getLogger("crawler.browser")

# ─── Configurações ────────────────────────────────────────────────

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

DEFAULT_VIEWPORT = {"width": 1280, "height": 800}


# ─── Browser Manager ──────────────────────────────────────────────

class BrowserManager:
    """
    Gerencia o ciclo de vida do Playwright Browser.
    """

    def __init__(self):
        self._playwright: Optional[PlaywrightContextManager] = None
        self._browser: Optional[Browser] = None
        self._lock = asyncio.Lock()

    async def start(self):
        async with self._lock:
            if self._browser and self._browser.is_connected():
                return

            logger.info("🚀 Iniciando Playwright...")

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-zygote",
                    "--disable-extensions",
                ],
            )

            logger.info("✅ Playwright pronto")

    async def stop(self):
        async with self._lock:
            if self._browser:
                await self._browser.close()
                self._browser = None

            if self._playwright:
                await self._playwright.stop()
                self._playwright = None

            logger.info("🛑 Playwright encerrado")

    @property
    def is_ready(self) -> bool:
        return self._browser is not None and self._browser.is_connected()

    @asynccontextmanager
    async def new_context(self):
        if not self.is_ready:
            await self.start()

        context: BrowserContext = await self._browser.new_context(
            user_agent=DEFAULT_USER_AGENT,
            viewport=DEFAULT_VIEWPORT,
            ignore_https_errors=False,
            java_script_enabled=True,
            bypass_csp=False,
            locale="pt-BR",
            timezone_id="America/Sao_Paulo",
            extra_http_headers={
                "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            },
        )

        # 🔥 BLOQUEIO DE RECURSOS PESADOS (performance + segurança)
        await context.route(
            "**/*",
            lambda route: (
                route.abort()
                if route.request.resource_type in ["image", "media", "font"]
                else route.continue_()
            ),
        )

        try:
            yield context
        finally:
            await context.close()


# ─── Page Crawler ─────────────────────────────────────────────────

class PageCrawler:
    def __init__(self, context: BrowserContext):
        self._context = context

    async def _build_redirect_chain(self, response: Optional[Response]) -> List[str]:
        """Constrói cadeia real de redirects"""
        chain = []

        current = response
        while current:
            chain.append(current.url)
            request = current.request

            if request.redirected_from:
                current = await request.redirected_from.response()
            else:
                break

        return list(reversed(chain))

    async def crawl(
        self,
        url: str,
        timeout: int = 20000,
        wait_for: Optional[str] = None,
        take_screenshot: bool = False,
    ) -> Tuple[Page, List[str], Optional[bytes], Optional[int]]:
        """
        Retorna:
        - page
        - redirect_chain
        - screenshot_bytes
        - status_code
        """

        page: Page = await self._context.new_page()

        try:
            response = await page.goto(
                url,
                timeout=timeout,
                wait_until="domcontentloaded",
            )

            # Status HTTP real
            status_code = response.status if response else None

            # Redirect chain real
            redirect_chain = await self._build_redirect_chain(response)

            # Espera seletor se necessário
            if wait_for:
                try:
                    await page.wait_for_selector(wait_for, timeout=5000)
                except PlaywrightTimeoutError:
                    logger.warning(f"Seletor '{wait_for}' não encontrado em {url}")

            # Espera JS básico
            await page.wait_for_timeout(800)

            final_url = page.url

            if final_url not in redirect_chain:
                redirect_chain.append(final_url)

            # 🔐 Flag de segurança básica
            if not final_url.startswith("https://"):
                logger.warning(f"⚠️ Site sem HTTPS: {final_url}")

            # Screenshot opcional
            screenshot_bytes: Optional[bytes] = None
            if take_screenshot:
                try:
                    screenshot_bytes = await page.screenshot(
                        timeout=5000,
                        type="jpeg",
                        quality=60,
                    )
                except Exception:
                    logger.warning("Falha ao capturar screenshot")

            return page, redirect_chain, screenshot_bytes, status_code

        except PlaywrightTimeoutError as e:
            raise TimeoutError(f"Timeout ao carregar {url}: {e}") from e

        except PlaywrightError as e:
            raise RuntimeError(f"Erro do Playwright em {url}: {e}") from e


# ─── Instância global ─────────────────────────────────────────────

browser_manager = BrowserManager()
