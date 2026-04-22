"""Script de seed para BrandProfile com marcas angolanas."""

from __future__ import annotations

import logging

from sqlmodel import Session, select

from backend.core.database import engine
from backend.models.brand import BrandProfile, DEFAULT_BRANDS

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("seed_brands")


def seed_brands() -> None:
    with Session(engine) as session:
        for item in DEFAULT_BRANDS:
            existing = session.exec(select(BrandProfile).where(BrandProfile.name == str(item["name"]))).first()
            if existing:
                logger.info("Marca já existe, ignorando: %s", existing.name)
                continue

            session.add(
                BrandProfile(
                    name=str(item["name"]),
                    official_domains=list(item["official_domains"]),
                    keywords=list(item["keywords"]),
                )
            )
            logger.info("Marca adicionada: %s", item["name"])

        session.commit()
        logger.info("Seed finalizado com sucesso.")


if __name__ == "__main__":
    seed_brands()
