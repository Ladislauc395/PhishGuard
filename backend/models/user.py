"""Modelo de utilizador para autenticação (PostgreSQL)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, DateTime, String, Text
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True)

    # VARCHAR com limite — eficiente para índices no Postgres
    name: str = Field(sa_column=Column(String(120), nullable=False))
    email: str = Field(
        sa_column=Column(String(254), unique=True, index=True, nullable=False)
    )

    # TEXT — hash bcrypt tem ~60 chars mas Text é mais seguro para futuro
    hashed_password: Optional[str] = Field(
        default=None, sa_column=Column(Text, nullable=True)
    )

    # Google OAuth
    google_id: Optional[str] = Field(
        default=None,
        sa_column=Column(String(128), unique=True, index=True, nullable=True),
    )
    avatar_url: Optional[str] = Field(
        default=None, sa_column=Column(Text, nullable=True)
    )

    # "local" | "google"
    provider: str = Field(
        sa_column=Column(String(20), nullable=False, server_default="local")
    )

    # TIMESTAMPTZ — guarda fuso horário no Postgres
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    