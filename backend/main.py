"""Aplicação principal FastAPI do PhishGuard."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import select

from backend.core.config import settings
from backend.core.database import create_db_and_tables, session_scope
from backend.models.brand import BrandProfile, DEFAULT_BRANDS
from backend.routers import analyze, dashboard


logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
)
logger = logging.getLogger(__name__)


def seed_brands_if_empty() -> None:
    """Garante que as marcas iniciais existam na base."""
    with session_scope() as session:
        existing = session.exec(select(BrandProfile)).all()
        if existing:
            logger.info("Seed de marcas ignorado: já existem %s registos.", len(existing))
            return

        for entry in DEFAULT_BRANDS:
            session.add(
                BrandProfile(
                    name=str(entry["name"]),
                    official_domains=list(entry["official_domains"]),
                    keywords=list(entry["keywords"]),
                )
            )
        logger.info("Seed inicial concluído com %s marcas angolanas.", len(DEFAULT_BRANDS))


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    create_db_and_tables()
    seed_brands_if_empty()
    logger.info("Aplicação PhishGuard inicializada com sucesso.")
    yield
    logger.info("Encerrando aplicação PhishGuard.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)

app.include_router(analyze.router, prefix=settings.api_prefix)
app.include_router(dashboard.router, prefix=settings.api_prefix)


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "phishguard-backend"}
