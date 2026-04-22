"""Modelos de análise de phishing."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel


class AnalysisBase(SQLModel):
    url: Optional[str] = Field(default=None, max_length=2048, index=True)
    channel: str = Field(max_length=20, index=True)
    score: int = Field(ge=0, le=100, index=True)
    verdict: str = Field(max_length=20, index=True)
    details: Dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))


class Analysis(AnalysisBase, table=True):
    __tablename__ = "analyses"

    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class AnalysisRead(AnalysisBase):
    id: int
    timestamp: datetime


class AnalysisCreate(AnalysisBase):
    pass
