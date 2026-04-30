"""
Verificação WHOIS robusta com python-whois.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import whois

logger = logging.getLogger(__name__)


def _normalize_creation_date(creation):
    """
    Normaliza creation_date para datetime válido.
    """

    if not creation:
        return None

    # lista → pega a mais antiga (mais confiável)
    if isinstance(creation, list):
        creation = min(
            [d for d in creation if isinstance(d, datetime)],
            default=None
        )

    if not isinstance(creation, datetime):
        return None

    # garantir timezone
    if creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)

    return creation


def get_domain_age_days(domain: str) -> Optional[int]:
    """
    Retorna idade do domínio em dias.

    Returns:
        int → idade em dias
        None → não foi possível determinar
    """

    try:
        w = whois.whois(domain)
        creation = _normalize_creation_date(w.creation_date)

        if not creation:
            logger.debug("Sem creation_date para %s", domain)
            return None

        now = datetime.now(timezone.utc)

        # 🔴 evitar datas inválidas
        if creation > now:
            logger.warning("Data de criação no futuro: %s", domain)
            return None

        age_days = (now - creation).days

        # 🔴 sanity check (ex: 1970)
        if age_days < 0 or age_days > 36500:
            logger.warning("Idade suspeita para %s: %s dias", domain, age_days)
            return None

        return age_days

    except Exception as exc:
        logger.warning("WHOIS falhou para %s: %s", domain, exc)
        return None

    