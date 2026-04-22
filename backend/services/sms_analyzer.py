"""Analisador heurístico de SMS para detecção de fraude."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

SUSPICIOUS_KEYWORDS = [
    "ganhou",
    "prémio",
    "premio",
    "clique aqui",
    "multicaixa express",
    "urgente",
    "confirme agora",
    "atualize a sua conta",
    "atualize sua conta",
]

URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)


@dataclass(slots=True)
class SMSAnalysisResult:
    has_url: bool
    matched_keywords: List[str]
    suspicious_pattern: bool
    details: Dict[str, str | bool | List[str]]


def analyze_sms_content(body: str) -> SMSAnalysisResult:
    """Analisa conteúdo SMS procurando padrão de engenharia social com URL."""
    normalized = (body or "").strip().lower()
    urls = URL_REGEX.findall(normalized)
    has_url = bool(urls)

    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in normalized]
    suspicious_pattern = has_url and len(matched_keywords) > 0

    details: Dict[str, str | bool | List[str]] = {
        "has_url": has_url,
        "urls_found": urls,
        "matched_keywords": matched_keywords,
        "suspicious_pattern": suspicious_pattern,
    }

    return SMSAnalysisResult(
        has_url=has_url,
        matched_keywords=matched_keywords,
        suspicious_pattern=suspicious_pattern,
        details=details,
    )
