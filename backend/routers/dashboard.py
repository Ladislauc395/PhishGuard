"""Endpoints de dashboard/estatísticas."""

from __future__ import annotations

import logging
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlmodel import Session, select

from backend.core.database import get_session
from backend.models.analysis import Analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class StatsResponse(BaseModel):
    total_analyses: int
    total_safe: int
    total_unsafe: int
    unsafe_rate_percent: float
    by_channel: Dict[str, int]
    by_verdict: Dict[str, int]


@router.get("/stats", response_model=StatsResponse)
async def get_stats(session: Session = Depends(get_session)) -> StatsResponse:
    try:
        total_analyses = session.exec(select(func.count(Analysis.id))).one() or 0
        total_safe = (
            session.exec(select(func.count(Analysis.id)).where(Analysis.verdict == "SEGURO")).one() or 0
        )
        total_unsafe = (
            session.exec(select(func.count(Analysis.id)).where(Analysis.verdict == "NÃO SEGURO")).one()
            or 0
        )

        by_channel_rows = session.exec(
            select(Analysis.channel, func.count(Analysis.id)).group_by(Analysis.channel)
        ).all()
        by_channel = {channel: count for channel, count in by_channel_rows}

        by_verdict_rows = session.exec(
            select(Analysis.verdict, func.count(Analysis.id)).group_by(Analysis.verdict)
        ).all()
        by_verdict = {verdict: count for verdict, count in by_verdict_rows}

        unsafe_rate_percent = round((total_unsafe / total_analyses) * 100, 2) if total_analyses else 0.0

        return StatsResponse(
            total_analyses=total_analyses,
            total_safe=total_safe,
            total_unsafe=total_unsafe,
            unsafe_rate_percent=unsafe_rate_percent,
            by_channel=by_channel,
            by_verdict=by_verdict,
        )
    except Exception as exc:
        logger.exception("Erro ao gerar estatísticas: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao obter estatísticas.",
        )
