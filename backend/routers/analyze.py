"""Endpoints de análise (URL, SMS, Email)."""

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
from backend.services.email_analyzer import analyze_email
from backend.services.heuristics import evaluate_domain
from backend.services.scoring import score_email_analysis, score_sms_analysis, score_url_analysis
from backend.services.sms_analyzer import analyze_sms_content

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["analyze"])


class AnalyzeURLRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048, examples=["https://bai.ao/login"])


class AnalyzeSMSRequest(BaseModel):
    body: str = Field(min_length=2, max_length=2000)
    phone_number: Optional[str] = Field(default=None, max_length=40)


class AnalyzeEmailRequest(BaseModel):
    sender: EmailStr
    subject: Optional[str] = Field(default=None, max_length=500)
    headers: str = Field(min_length=3, max_length=20000)
    body: Optional[str] = Field(default=None, max_length=50000)


class AnalyzeResponse(BaseModel):
    score: int
    verdict: str
    details: Dict[str, Any]
    analysis_id: int
    timestamp: datetime

    model_config = {
        "json_schema_extra": {
            "example": {
                "score": 80,
                "verdict": "NÃO SEGURO",
                "details": {"triggered_rule": "TYPOSQUATTING"},
                "analysis_id": 1,
                "timestamp": "2026-04-22T10:00:00Z",
            }
        }
    }


def _get_brands(session: Session) -> List[BrandProfile]:
    return session.exec(select(BrandProfile)).all()


def _safe_analysis_id(analysis: Analysis) -> int:
    if analysis.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao persistir análise.",
        )
    return analysis.id


@router.post("/url", response_model=AnalyzeResponse)
async def analyze_url(payload: AnalyzeURLRequest, session: Session = Depends(get_session)) -> AnalyzeResponse:
    try:
        brands = _get_brands(session)
        domain_result = await evaluate_domain(payload.url, brands)
        score_result = score_url_analysis(domain_result)

        analysis = Analysis(
            url=payload.url,
            channel="web",
            score=score_result.score,
            verdict=score_result.verdict,
            details=score_result.details,
        )
        session.add(analysis)
        session.commit()
        session.refresh(analysis)

        logger.info(
            "URL analisada",
            extra={
                "analysis_id": analysis.id,
                "channel": "web",
                "score": score_result.score,
                "verdict": score_result.verdict,
            },
        )

        return AnalyzeResponse(
            score=score_result.score,
            verdict=score_result.verdict,
            details=score_result.details,
            analysis_id=_safe_analysis_id(analysis),
            timestamp=analysis.timestamp,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Falha ao analisar URL: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar análise de URL.",
        )


@router.post("/sms", response_model=AnalyzeResponse)
async def analyze_sms(payload: AnalyzeSMSRequest, session: Session = Depends(get_session)) -> AnalyzeResponse:
    try:
        sms_result = analyze_sms_content(payload.body)
        score_result = score_sms_analysis(sms_result)

        analysis = Analysis(
            channel="sms",
            score=score_result.score,
            verdict=score_result.verdict,
            details=score_result.details,
        )
        session.add(analysis)
        session.commit()
        session.refresh(analysis)

        analysis_id = _safe_analysis_id(analysis)
        sms_entry = SMS(
            phone_number=payload.phone_number,
            body=payload.body,
            analysis_id=analysis_id,
        )
        session.add(sms_entry)
        session.commit()

        return AnalyzeResponse(
            score=score_result.score,
            verdict=score_result.verdict,
            details=score_result.details,
            analysis_id=analysis_id,
            timestamp=analysis.timestamp,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Falha ao analisar SMS: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar análise de SMS.",
        )


@router.post("/email", response_model=AnalyzeResponse)
async def analyze_email_endpoint(
    payload: AnalyzeEmailRequest,
    session: Session = Depends(get_session),
) -> AnalyzeResponse:
    try:
        brands = _get_brands(session)
        email_result = analyze_email(raw_headers=payload.headers, body=payload.body, brands=brands)
        score_result = score_email_analysis(email_result)

        analysis = Analysis(
            channel="email",
            score=score_result.score,
            verdict=score_result.verdict,
            details=score_result.details,
        )
        session.add(analysis)
        session.commit()
        session.refresh(analysis)

        analysis_id = _safe_analysis_id(analysis)
        email_entry = Email(
            sender=str(payload.sender),
            subject=payload.subject,
            headers=payload.headers,
            body=payload.body,
            analysis_id=analysis_id,
        )
        session.add(email_entry)
        session.commit()

        return AnalyzeResponse(
            score=score_result.score,
            verdict=score_result.verdict,
            details=score_result.details,
            analysis_id=analysis_id,
            timestamp=analysis.timestamp,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Falha ao analisar email: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar análise de e-mail.",
        )
