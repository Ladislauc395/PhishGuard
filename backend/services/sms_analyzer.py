"""
Analisador de SMS para detecção de smishing.

Pipeline:
  1. Validar número via Twilio Lookup
  2. Validar número via NumVerify (fallback / dupla verificação)
  3. Extrair e analisar links com analyze_url()
     — inclui agora Google Safe Browsing e DNSBL via reputation.py
  4. Detectar palavras-chave de engenharia social
  5. Detectar Sender ID alfanumérico suspeito (SMS Spoofing)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Dict, List, Tuple

import requests

from backend.services.scoring import classify_score

logger = logging.getLogger(__name__)

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN", "")
NUMVERIFY_API_KEY  = os.getenv("NUMVERIFY_API_KEY", "")

URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)

# ─── Palavras-chave de engenharia social ──────────────────────────
# Expandidas para cobrir padrões comuns em Angola/PT e internacionais.
SUSPICIOUS_KEYWORDS = [
    # Urgência / ação imediata
    "urgente",
    "clique agora",
    "clique aqui",
    "aceda agora",
    "imediato",
    "último aviso",
    "ação necessária",
    # Conta / acesso
    "conta bloqueada",
    "acesso suspenso",
    "conta suspensa",
    "suspensa",
    "verifique",
    "confirme agora",
    "senha expirada",
    "palavra-passe expirada",
    "atualize a sua conta",
    "atualize sua conta",
    "atualizar dados",
    # Prémios / fraude financeira
    "ganhou",
    "prémio",
    "premio",
    "parabéns",
    "transferência aprovada",
    "reembolso disponível",
    "pagamento pendente",
    # Marcas angolanas frequentemente imitadas
    "multicaixa express",
    "multicaixa",
    "bai directo",
    "unitel money",
    "africell money",
    # Internacionais comuns em smishing
    "paypal",
    "amazon",
    "dhl",
    "fedex",
    "encomenda retida",
    "package held",
    "verify your account",
    "click here",
    "act now",
    "limited time",
]

# Sender IDs alfanuméricos conhecidos como legítimos em Angola
# (evita penalizar SMS de bancos/operadoras reais)
LEGITIMATE_SENDER_IDS = {
    "BAI", "BFA", "BPC", "ATLANTICO", "BIC",
    "UNITEL", "MOVICEL", "AFRICELL",
    "MULTICAIXA", "EMIS",
}

REQUEST_TIMEOUT = 6


# ─── Validação de número ──────────────────────────────────────────

def _validate_twilio(phone: str) -> Tuple[bool, bool]:
    """
    Valida número via Twilio Lookup API.
    Retorna (valid, has_carrier).
    """
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        logger.debug("Twilio não configurado")
        return True, True

    try:
        resp = requests.get(
            f"https://lookups.twilio.com/v1/PhoneNumbers/{phone}",
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            params={"Type": "carrier"},
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 404:
            return False, False

        resp.raise_for_status()
        data       = resp.json()
        carrier    = data.get("carrier") or {}
        has_carrier = bool(carrier.get("name"))
        return True, has_carrier

    except Exception as exc:
        logger.warning("Twilio lookup falhou: %s", exc)
        return True, True


def _validate_numverify(phone: str) -> bool:
    """
    Valida número via NumVerify.
    Retorna True se válido.
    """
    if not NUMVERIFY_API_KEY:
        logger.debug("NumVerify não configurado")
        return True

    try:
        resp = requests.get(
            "http://apilayer.net/api/validate",
            params={"access_key": NUMVERIFY_API_KEY, "number": phone},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get("valid", True))

    except Exception as exc:
        logger.warning("NumVerify falhou: %s", exc)
        return True


# ─── Detecção de Sender ID suspeito (NOVO) ───────────────────────
# Conforme documentado nas imagens:
# "Sender ID alfanumérico — Ex: 'BRADESCO' — pode ser falsificado (SMS spoofing)"
# Se o remetente não for numérico E não constar na whitelist → suspeito.

def _check_sender_id(sender: str) -> Tuple[bool, str]:
    """
    Verifica se o Sender ID alfanumérico é suspeito.

    Returns:
        (is_suspicious, reason)
    """
    if not sender:
        return False, ""

    # Remetente numérico (número de telefone normal) — não suspeito por si só
    if re.fullmatch(r"[\d\+\-\s\(\)]+", sender.strip()):
        return False, ""

    # Sender ID alfanumérico — verificar contra whitelist
    sender_upper = sender.strip().upper()

    if sender_upper in LEGITIMATE_SENDER_IDS:
        return False, ""  # legítimo

    # Alfanumérico desconhecido — potencial SMS spoofing
    return True, f"unknown_alphanumeric_sender:{sender}"


# ─── Função principal ─────────────────────────────────────────────

def analyze_sms(message: str, sender: str) -> dict:
    """
    Analisa SMS para detecção de smishing.

    Args:
        message: corpo do SMS
        sender:  número ou ID do remetente

    Retorna:
    {
        "score": int,
        "classification": "safe" | "suspicious" | "phishing",
        "reasons": List[str],
        "url_analysis": List[dict]
    }
    """
    from backend.services.url_analyzer import analyze_url

    score   = 0
    reasons: List[str] = []

    normalized_message = (message or "").lower().strip()

    # ── Etapa 1: Twilio ──
    twilio_valid, has_carrier = _validate_twilio(sender)
    if not twilio_valid:
        score += 40
        reasons.append("invalid_phone_number:twilio")
    elif not has_carrier:
        score += 20
        reasons.append("no_carrier_detected:twilio")

    # ── Etapa 2: NumVerify ──
    numverify_valid = _validate_numverify(sender)
    if not numverify_valid:
        score += 40
        reasons.append("invalid_phone_number:numverify")

    # ── Etapa 3: Sender ID alfanumérico suspeito (NOVO) ──
    # Conforme "O que analisar no SMS" → "Sender ID alfanumérico"
    sender_suspicious, sender_reason = _check_sender_id(sender)
    if sender_suspicious:
        score += 25
        reasons.append(sender_reason)

    # ── Etapa 4: Links ──
    # analyze_url agora inclui Google Safe Browsing e DNSBL automaticamente
    urls = URL_REGEX.findall(normalized_message)
    url_results: List[Dict] = []

    for url in urls:
        try:
            result = analyze_url(url)
            url_results.append(result)

            url_contribution = int(result["score"] * 0.5)
            if url_contribution > 0:
                score += url_contribution
                reasons.append(
                    f"suspicious_url:{url} "
                    f"(score={result['score']}, "
                    f"classification={result['classification']})"
                )
        except Exception as exc:
            logger.warning("Erro ao analisar URL do SMS %s: %s", url, exc)

    # ── Etapa 5: Palavras-chave de engenharia social ──
    # Score proporcional ao número de keywords detetadas (mais keywords = mais suspeito)
    matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw in normalized_message]
    if matched:
        keyword_score = min(20 + (len(matched) - 1) * 5, 40)  # 20 base, +5 por keyword extra, máx 40
        score += keyword_score
        reasons.append(f"suspicious_keywords:{','.join(matched)}")

    score = min(score, 100)

    return {
        "score":           score,
        "classification":  classify_score(score),
        "reasons":         reasons,
        "url_analysis":    url_results,
    }
