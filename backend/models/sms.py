"""Modelo para armazenamento de SMS analisados."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class SMSBase(SQLModel):
    phone_number: Optional[str] = Field(default=None, max_length=40, index=True)
    body: str = Field(max_length=2000)


class SMS(SMSBase, table=True):
    __tablename__ = "sms_messages"

    id: Optional[int] = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id", index=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)


class SMSCreate(SMSBase):
    pass


class SMSRead(SMSBase):
    id: int
    analysis_id: int
    timestamp: datetime
