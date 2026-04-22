"""Modelo para e-mails submetidos para análise."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class EmailBase(SQLModel):
    sender: str = Field(max_length=255, index=True)
    subject: Optional[str] = Field(default=None, max_length=500)
    headers: str = Field(max_length=20000)
    body: Optional[str] = Field(default=None, max_length=50000)


class Email(EmailBase, table=True):
    __tablename__ = "emails"

    id: Optional[int] = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id", index=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class EmailCreate(EmailBase):
    pass


class EmailRead(EmailBase):
    id: int
    analysis_id: int
    timestamp: datetime
