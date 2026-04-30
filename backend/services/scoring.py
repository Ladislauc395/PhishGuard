"""
Sistema de pontuação e classificação do PhishGuard.

Patamares:
  0–30  → safe
  31–70 → suspicious
  71+   → phishing

REGRAS:
- Score é acumulativo
- NÃO assumir safe por ausência em blacklist
- Sistema preparado para ML híbrido (heurística + modelo)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


# ─── Thresholds ───────────────────────────────────────────────────

THRESHOLD_SUSPICIOUS = 31
THRESHOLD_PHISHING = 71


# ─── Reason estruturado ───────────────────────────────────────────

@dataclass(frozen=True)
class Reason:
    code: str
    weight: int
    description: str


# ─── Catálogo de razões ───────────────────────────────────────────

REASONS: Dict[str, Reason] = {
    "domain_not_found":     Reason("domain_not_found",     80, "Domínio não existe"),
    "no_http_response":     Reason("no_http_response",     60, "Sem resposta HTTP"),
    "new_domain":           Reason("new_domain",           40, "Domínio recente"),
    "very_new_domain":      Reason("very_new_domain",      70, "Domínio muito recente"),
    "low_content":          Reason("low_content",          40, "Conteúdo muito baixo"),
    "brand_spoofing":       Reason("brand_spoofing",       90, "Spoofing de marca"),
    "malicious_reputation": Reason("malicious_reputation", 80, "Reputação maliciosa"),
    "url_shortener":        Reason("url_shortener",        30, "Uso de encurtador"),
    "domain_mismatch":      Reason("domain_mismatch",      50, "Domínio não corresponde"),
}


# ─── Classification ───────────────────────────────────────────────

def classify_score(score: int) -> str:
    if score >= THRESHOLD_PHISHING:
        return "phishing"
    elif score >= THRESHOLD_SUSPICIOUS:
        return "suspicious"
    return "safe"


def _verdict(score: int) -> str:
    """Converte score em veredicto legível para a BD e para o Flutter."""
    if score >= THRESHOLD_PHISHING:
        return "NÃO SEGURO"
    elif score >= THRESHOLD_SUSPICIOUS:
        return "SUSPEITO"
    return "SEGURO"


# ─── Score Builder (núcleo do sistema) ────────────────────────────

class ScoreBuilder:
    def __init__(self) -> None:
        self._score: int = 0
        self._reasons: List[str] = []
        self._details: Dict[str, Any] = {}

    def add(self, code: str, extra: int = 0) -> None:
        reason = REASONS.get(code)
        if not reason:
            return
        self._score += reason.weight + extra
        self._reasons.append(code)

    def add_raw(self, value: int, label: str) -> None:
        self._score += value
        self._reasons.append(f"raw:{label}:{value}")

    def set_detail(self, key: str, value: Any) -> None:
        self._details[key] = value

    def build(self) -> "ScoreResult":
        return ScoreResult.from_score(
            score=self._score,
            reasons=self._reasons,
            details=self._details,
        )


# ─── Result Model ─────────────────────────────────────────────────

@dataclass
class ScoreResult:
    score: int
    classification: str
    verdict: str
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    raw_score: int = 0

    @classmethod
    def from_score(
        cls,
        score: int,
        reasons: List[str],
        details: Dict[str, Any] | None = None,
    ) -> "ScoreResult":
        raw_score = score
        normalized = max(0, min(score, 100))
        return cls(
            score=normalized,
            raw_score=raw_score,
            classification=classify_score(normalized),
            verdict=_verdict(normalized),
            reasons=list(dict.fromkeys(reasons)),
            details=details or {},
        )


# ─── Adaptadores para os routers ──────────────────────────────────
#
# Recebem o dict devolvido pelos analisadores existentes
# (url_analyzer, sms_analyzer, email_analyzer) e produzem
# um ScoreResult compatível com a BD (Analysis.verdict, Analysis.details).

def score_url_analysis(domain_result: Any) -> ScoreResult:
    """
    Converte o resultado de heuristics.evaluate_domain() em ScoreResult.

    domain_result é um DomainCheckResult (dataclass com slots):
      .domain, .dns_resolves, .typosquatting_detected,
      .suspected_brand, .official_match, .reason
    """
    score = 0
    reasons: List[str] = []
    details: Dict[str, Any] = {
        "domain":                domain_result.domain,
        "dns_resolves":          domain_result.dns_resolves,
        "typosquatting":         domain_result.typosquatting_detected,
        "suspected_brand":       domain_result.suspected_brand,
        "official_match":        domain_result.official_match,
        "reason":                domain_result.reason,
    }

    if not domain_result.dns_resolves:
        score += REASONS["domain_not_found"].weight
        reasons.append("domain_not_found")

    if domain_result.typosquatting_detected:
        score += REASONS["brand_spoofing"].weight
        reasons.append("brand_spoofing")

    if domain_result.suspected_brand and not domain_result.official_match:
        # Marca detectada mas domínio não é oficial → suspeito
        score += 40
        reasons.append("brand_domain_mismatch")

    if not reasons:
        reasons.append("no_signals")

    return ScoreResult.from_score(score=score, reasons=reasons, details=details)


def score_sms_analysis(sms_result: Dict[str, Any]) -> ScoreResult:
    """
    Converte o dict devolvido por sms_analyzer.analyze_sms() em ScoreResult.

    sms_result = {
        "score": int,
        "classification": str,
        "reasons": List[str],
        "url_analysis": List[dict],
    }
    """
    score = sms_result.get("score", 0)
    reasons = sms_result.get("reasons", [])
    details: Dict[str, Any] = {
        "classification": sms_result.get("classification"),
        "url_analysis":   sms_result.get("url_analysis", []),
    }
    return ScoreResult.from_score(score=score, reasons=reasons, details=details)


def score_email_analysis(email_result: Dict[str, Any]) -> ScoreResult:
    """
    Converte o dict devolvido por email_analyzer.analyze_email() em ScoreResult.

    email_result = {
        "score": int,
        "classification": str,
        "reasons": List[str],
        "auth": {"spf": bool, "dkim": bool, "dmarc": bool},
        "urls_found": List[str],
        "url_analysis": List[dict],
    }
    """
    score = email_result.get("score", 0)
    reasons = email_result.get("reasons", [])
    details: Dict[str, Any] = {
        "classification": email_result.get("classification"),
        "auth":           email_result.get("auth", {}),
        "urls_found":     email_result.get("urls_found", []),
        "url_analysis":   email_result.get("url_analysis", []),
    }
    return ScoreResult.from_score(score=score, reasons=reasons, details=details)


# ─── (Opcional) Integração ML híbrido ─────────────────────────────

def combine_with_ml(heuristic_score: int, ml_probability: float) -> int:
    ml_score = ml_probability * 100
    final = (heuristic_score * 0.6) + (ml_score * 0.4)
    return int(max(0, min(final, 100)))

