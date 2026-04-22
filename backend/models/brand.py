"""Modelo de perfil de marcas protegidas pelo PhishGuard."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlmodel import Field, SQLModel


class BrandProfileBase(SQLModel):
    name: str = Field(max_length=120, unique=True, index=True)
    official_domains: List[str] = Field(sa_column=Column(ARRAY(Text), nullable=False))
    keywords: List[str] = Field(sa_column=Column(ARRAY(Text), nullable=False))


class BrandProfile(BrandProfileBase, table=True):
    __tablename__ = "brand_profiles"

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class BrandProfileRead(BrandProfileBase):
    id: int
    created_at: datetime


DEFAULT_BRANDS: List[dict[str, list[str] | str]] = [
    {
        "name": "BAI",
        "official_domains": ["bai.ao"],
        "keywords": ["bai", "banco angolano de investimentos"],
    },
    {
        "name": "BFA",
        "official_domains": ["bfa.ao"],
        "keywords": ["bfa", "banco de fomento angola"],
    },
    {
        "name": "BPC",
        "official_domains": ["bpc.ao"],
        "keywords": ["bpc", "banco de poupanca e credito", "banco de poupança e crédito"],
    },
    {
        "name": "Banco SOL",
        "official_domains": ["bancosol.ao"],
        "keywords": ["banco sol", "bancosol", "sol"],
    },
    {
        "name": "Multicaixa Express",
        "official_domains": ["multicaixa.ao"],
        "keywords": ["multicaixa", "multicaixa express"],
    },
    {
        "name": "Unitel",
        "official_domains": ["unitel.ao"],
        "keywords": ["unitel"],
    },
    {
        "name": "Africell",
        "official_domains": ["africell.ao"],
        "keywords": ["africell"],
    },
    {
        "name": "Zap",
        "official_domains": ["zap.co.ao"],
        "keywords": ["zap", "zap fibra", "zap tv"],
    },
    {
        "name": "AGT",
        "official_domains": ["agt.gov.ao"],
        "keywords": ["agt", "administração geral tributária", "administracao geral tributaria"],
    },
]
