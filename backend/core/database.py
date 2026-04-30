"""Configuração de banco de dados com SQLModel."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator

from sqlmodel import Session, SQLModel, create_engine

from backend.core.config import settings

logger = logging.getLogger(__name__)

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
)


def create_db_and_tables() -> None:
    """Cria todas as tabelas mapeadas pelos modelos SQLModel."""
    try:
        # Import local para garantir que os modelos sejam registrados antes da criação.
        from backend.models import analysis, brand, email, sms, user  # noqa: F401

        SQLModel.metadata.create_all(engine)
        logger.info("Tabelas criadas/verificadas com sucesso.")
    except Exception as exc:  # pragma: no cover - proteção adicional
        logger.exception("Falha ao criar tabelas: %s", exc)
        raise


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Context manager para operações transacionais."""
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Generator[Session, None, None]:
    """Dependency do FastAPI para injeção de sessão."""
    with Session(engine) as session:
        yield session


        
