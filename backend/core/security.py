"""Funções de segurança para uso atual e preparação da Fase 2."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Final


HASH_ITERATIONS: Final[int] = 390000
SALT_LENGTH: Final[int] = 16
EMAIL_REGEX: Final[re.Pattern[str]] = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def generate_salt() -> str:
    """Gera salt criptográfico em hexadecimal."""
    return secrets.token_hex(SALT_LENGTH)


def hash_password(password: str, salt: str | None = None) -> str:
    """
    Gera hash seguro para senha com PBKDF2-HMAC-SHA256.

    Formato de retorno: pbkdf2_sha256$iteracoes$salt$hash
    """
    if not password or len(password) < 8:
        raise ValueError("A senha deve ter no mínimo 8 caracteres.")

    selected_salt = salt or generate_salt()
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        selected_salt.encode("utf-8"),
        HASH_ITERATIONS,
    )
    return f"pbkdf2_sha256${HASH_ITERATIONS}${selected_salt}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Valida senha comparando hash calculado vs hash armazenado."""
    try:
        algorithm, iterations_raw, salt, original_hash = password_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_raw)
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
        return hmac.compare_digest(new_hash, original_hash)
    except (ValueError, TypeError):
        return False


def validate_email_format(email: str) -> bool:
    """Validação simples de formato de e-mail."""
    if not email:
        return False
    return bool(EMAIL_REGEX.match(email.strip().lower()))


def generate_secret_key(length: int = 64) -> str:
    """Gera chave secreta aleatória para variáveis de ambiente."""
    if length < 32:
        raise ValueError("A chave secreta deve ter pelo menos 32 caracteres.")
    return secrets.token_urlsafe(length)


def constant_time_compare(value_a: str, value_b: str) -> bool:
    """Comparação em tempo constante para evitar timing attacks."""
    return hmac.compare_digest(value_a.encode("utf-8"), value_b.encode("utf-8"))
