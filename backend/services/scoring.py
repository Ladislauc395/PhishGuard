"""Serviço de pontuação e veredito binário do PhishGuard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from backend.services.email_analyzer import EmailAnalysisResult
from backend.services.heuristics import DomainCheckResult
from backend.services.sms_analyzer import SMSAnalysisResult

RISK_THRESHOLD = 60


@dataclass(slots=True)
class ScoreResult:
    score: int
    verdict: str
    details: Dict[str, Any]


def _verdict_from_score(score: int) -> str:
    return "NÃO SEGURO" if score >= RISK_THRESHOLD else "SEGURO"


def score_url_analysis(result: DomainCheckResult) -> ScoreResult:
    """Pontuação para análise de URL com base nas regras da Fase 1."""
    score = 0
    triggered_rule = "sem_regra"

    if not result.dns_resolves:
        score = 100
        triggered_rule = "DNS_FAIL"
    elif result.typosquatting_detected:
        score = 80
        triggered_rule = "TYPOSQUATTING"
    elif result.suspected_brand and not result.official_match:
        score = 100
        triggered_rule = "DOMINIO_NAO_OFICIAL"

    details = {
        "triggered_rule": triggered_rule,
        "domain": result.domain,
        "dns_resolves": result.dns_resolves,
        "suspected_brand": result.suspected_brand,
        "official_match": result.official_match,
        "typosquatting_detected": result.typosquatting_detected,
        "reason": result.reason,
    }
    return ScoreResult(score=score, verdict=_verdict_from_score(score), details=details)


def score_email_analysis(result: EmailAnalysisResult) -> ScoreResult:
    """Pontuação para e-mails com foco em autenticação e links."""
    auth_failed = not (result.spf_pass and result.dkim_pass and result.dmarc_pass)
    suspicious = auth_failed and result.suspicious_link_detected

    score = 70 if suspicious else 0
    details = {
        "triggered_rule": "SPF_DKIM_DMARC_FAIL_COM_LINK" if suspicious else "sem_regra",
        "auth_failed": auth_failed,
        "spf_pass": result.spf_pass,
        "dkim_pass": result.dkim_pass,
        "dmarc_pass": result.dmarc_pass,
        "suspicious_link_detected": result.suspicious_link_detected,
        "urls_found": result.urls_found,
    }
    return ScoreResult(score=score, verdict=_verdict_from_score(score), details=details)


def score_sms_analysis(result: SMSAnalysisResult) -> ScoreResult:
    """Pontuação para SMS usando palavra-chave + link."""
    suspicious = result.suspicious_pattern
    score = 65 if suspicious else 0

    details = {
        "triggered_rule": "PALAVRAS_CHAVE_SMS" if suspicious else "sem_regra",
        "has_url": result.has_url,
        "matched_keywords": result.matched_keywords,
        "suspicious_pattern": result.suspicious_pattern,
    }
    return ScoreResult(score=score, verdict=_verdict_from_score(score), details=details)
