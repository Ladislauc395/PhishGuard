"""Endpoints de análise (URL, SMS, Email) unificados com o Orquestrador."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlmodel import Session, select

from backend.core.database import get_session
from backend.models.analysis import Analysis
from backend.models.brand import BrandProfile
from backend.models.email import Email
from backend.models.sms import SMS

from backend.services.orchestrator import (
    orchestrate_url, 
    orchestrate_sms, 
    orchestrate_email
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["analyze"])


class AnalyzeURLRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048, examples=["https://bai.ao/login"])


class AnalyzeSMSRequest(BaseModel):
    body: Optional[str] = Field(default=None, max_length=2000)
    message: Optional[str] = Field(default=None, max_length=2000)
    phone_number: Optional[str] = Field(default=None, max_length=40)
    sender: Optional[str] = Field(default=None, max_length=40)

    @property
    def resolved_body(self) -> str:
        return self.body or self.message or ""

    @property
    def resolved_sender(self) -> str:
        return self.phone_number or self.sender or ""


class AnalyzeEmailRequest(BaseModel):
    sender: Optional[EmailStr] = Field(default=None)
    subject: Optional[str] = Field(default=None, max_length=500)
    headers: Optional[str] = Field(default=None, max_length=20000)
    raw_headers: Optional[str] = Field(default=None, max_length=20000)
    body: Optional[str] = Field(default=None, max_length=50000)

    @property
    def resolved_headers(self) -> str:
        return self.headers or self.raw_headers or ""


class AnalyzeResponse(BaseModel):
    score: int
    verdict: str
    classification: str
    reasons: List[str]
    details: Dict[str, Any]
    analysis_id: int
    timestamp: datetime


@router.post("/url", response_model=AnalyzeResponse)
async def analyze_url(
    payload: AnalyzeURLRequest,
    session: Session = Depends(get_session),
) -> AnalyzeResponse:
    try:
        result = await orchestrate_url(payload.url)

        analysis = Analysis(
            url=payload.url,
            channel="web",
            score=result["score"],
            verdict=result["verdict"],
            details=result,
        )
        session.add(analysis)
        session.commit()
        session.refresh(analysis)

        return AnalyzeResponse(
            score=result["score"],
            verdict=result["verdict"],
            classification="phishing" if result["score"] >= 60 else "safe",
            reasons=result.get("reasons", ["no_threats_detected"]),
            details=result,
            analysis_id=analysis.id,
            timestamp=analysis.timestamp,
        )
    except Exception as exc:
        logger.exception("Falha ao analisar URL: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro interno na análise de URL: {str(exc)}",
        )


@router.post("/sms", response_model=AnalyzeResponse)
async def analyze_sms(
    payload: AnalyzeSMSRequest,
    session: Session = Depends(get_session),
) -> AnalyzeResponse:
    try:
        body = payload.resolved_body
        sender = payload.resolved_sender

        if not body:
            raise HTTPException(status_code=422, detail="Corpo do SMS vazio")

        result = await orchestrate_sms(body, sender)

        analysis = Analysis(
            channel="sms",
            score=result["score"],
            verdict=result["verdict"],
            details=result,
        )
        session.add(analysis)
        session.commit()
        session.refresh(analysis)

        sms_entry = SMS(
            phone_number=sender,
            body=body,
            analysis_id=analysis.id,
        )
        session.add(sms_entry)
        session.commit()

        return AnalyzeResponse(
            score=result["score"],
            verdict=result["verdict"],
            classification="phishing" if result["score"] >= 60 else "safe",
            reasons=result.get("reasons", []),
            details=result,
            analysis_id=analysis.id,
            timestamp=analysis.timestamp,
        )
    except Exception as exc:
        logger.exception("Falha no SMS: %s", exc)
        raise HTTPException(status_code=500, detail="Erro no processamento de SMS")


@router.post("/email", response_model=AnalyzeResponse)
async def analyze_email_endpoint(
    payload: AnalyzeEmailRequest,
    session: Session = Depends(get_session),
) -> AnalyzeResponse:
    try:
        headers = payload.resolved_headers
        
        result = await orchestrate_email(str(payload.sender), headers, payload.body)

        analysis = Analysis(
            channel="email",
            score=result["score"],
            verdict=result["verdict"],
            details=result,
        )
        session.add(analysis)
        session.commit()
        session.refresh(analysis)

        email_entry = Email(
            sender=str(payload.sender),
            subject=payload.subject,
            headers=headers,
            body=payload.body,
            analysis_id=analysis.id,
        )
        session.add(email_entry)
        session.commit()

        return AnalyzeResponse(
            score=result["score"],
            verdict=result["verdict"],
            classification="phishing" if result["score"] >= 60 else "safe",
            reasons=result.get("reasons", []),
            details=result,
            analysis_id=analysis.id,
            timestamp=analysis.timestamp,
        )
    except Exception as exc:
        logger.exception("Falha no Email: %s", exc)
        raise HTTPException(status_code=500, detail="Erro no processamento de Email")
    