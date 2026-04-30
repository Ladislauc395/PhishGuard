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
from backend.routers.gmail_router import router as gmail_router   # ← NOVO
from backend.core.database import create_db_and_tables


# ─── Logging JSON ─────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
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
    create_db_and_tables()
    logger.info("Base de dados PostgreSQL pronta.")
    yield
    logger.info("PhishGuard API encerrada.")


# ─── App ──────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description=(
        "Detecção de phishing e smishing com score acumulado. "
        "NUNCA assume seguro por ausência em blacklist."
    ),
    version="2.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Routers ──────────────────────────────────────────────────────

app.include_router(auth_router)                                    # /auth/*
app.include_router(analyze_router)                                 # /analyze/*
app.include_router(dashboard_router)                               # /dashboard/*
app.include_router(integrations.router)                            # /integrations/*
app.include_router(extension_router, prefix="/extension")
# Gmail router registado com prefixo /integrations para que o Flutter
# encontre os endpoints nos URLs que já usa:
#   /integrations/auth/gmail/url
#   /integrations/auth/gmail/callback
#   /integrations/gmail/emails/all      ← getAllAnalysedEmails()
#   /integrations/gmail/emails/blocked  ← getBlockedEmails()
#   /integrations/gmail/scan
#   /integrations/gmail/unblock/{id}
app.include_router(gmail_router, prefix="/integrations")           # ← NOVO


# ─── Health ───────────────────────────────────────────────────────

@app.get("/health", tags=["Status"])
async def health():
    return {"status": "ok", "version": "2.1.0"}


# ─── Entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
    