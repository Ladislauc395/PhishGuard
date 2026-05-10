"""PhishGuard API — detecção de phishing e smishing."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routers.extension_router import router as extension_router
from backend.routers import integrations
from backend.routers.analyze import router as analyze_router
from backend.routers.dashboard import router as dashboard_router
from backend.routers.auth import router as auth_router
from backend.routers.gmail_router import router as gmail_router
from backend.routers.notifications_router import router as notifications_router
from backend.core.database import create_db_and_tables


# ─── Logging JSON ─────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "level":     record.levelname,
            "logger":    record.name,
            "message":   record.getMessage(),
        })


def _setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [handler]


_setup_logging()
logger = logging.getLogger("phishguard.main")


# ─── Lifespan ─────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Arrancar base de dados
    create_db_and_tables()
    logger.info("Base de dados PostgreSQL pronta.")

    # ── NOVIDADE: Auto-scan watcher ──────────────────────────────
    # Arrancar o watcher que verifica novos emails automaticamente
    # a cada 60 segundos e bloqueia phishing sem intervenção do utilizador.
    try:
        from backend.services.gmail_hook import start_auto_scan_watcher, is_gmail_connected
        if is_gmail_connected():
            start_auto_scan_watcher()
            logger.info("🤖 Auto-scan watcher iniciado no startup.")
        else:
            logger.warning(
                "⚠️ Gmail não conectado no startup — "
                "o watcher arrancará após autenticação via /auth/gmail/url"
            )
    except Exception as exc:
        logger.error("Erro ao iniciar auto-scan watcher: %s", exc)

    yield

    logger.info("PhishGuard API encerrada.")


# ─── App ──────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description=(
        "Detecção de phishing e smishing com score acumulado. "
        "NUNCA assume seguro por ausência em blacklist. "
        "Auto-scan activo — emails verificados a cada 60s."
    ),
    version="2.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Routers ──────────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(analyze_router)
app.include_router(dashboard_router)
app.include_router(integrations.router)
app.include_router(extension_router, prefix="/extension")
app.include_router(gmail_router, prefix="/integrations")
app.include_router(notifications_router)


# ─── Health ───────────────────────────────────────────────────────

@app.get("/health", tags=["Status"])
async def health():
    try:
        from backend.services.gmail_hook import get_gmail_diagnostics, _watcher_task
        diag = get_gmail_diagnostics()
        watcher_active = _watcher_task is not None and not _watcher_task.done()
    except Exception:
        diag           = {}
        watcher_active = False

    return {
        "status":         "ok",
        "version":        "2.2.0",
        "auto_scan":      watcher_active,
        "gmail_connected": diag.get("connected", False),
    }


# ─── Entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
    