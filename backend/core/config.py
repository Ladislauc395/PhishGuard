"""Configurações centrais da aplicação PhishGuard."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from dotenv import load_dotenv


load_dotenv()


@dataclass(slots=True)
class Settings:
    """Estrutura de configurações carregadas por variáveis de ambiente."""

    app_name: str = os.getenv("APP_NAME", "PhishGuard API")
    app_version: str = os.getenv("APP_VERSION", "1.0.0")
    app_env: str = os.getenv("APP_ENV", "development")
    debug: bool = os.getenv("DEBUG", "false").lower() in {"1", "true", "yes"}

    api_prefix: str = os.getenv("API_PREFIX", "/api")

    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://phishguard_user:phishguard_password@localhost:5432/phishguard",
    )

    secret_key: str = os.getenv(
        "SECRET_KEY",
        "trocar-em-producao-chave-secreta-phishguard",
    )
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    cors_origins_raw: str = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    )
    cors_allow_credentials: bool = (
        os.getenv("CORS_ALLOW_CREDENTIALS", "true").lower() in {"1", "true", "yes"}
    )
    cors_allow_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    cors_allow_headers: List[str] = field(
        default_factory=lambda: ["Authorization", "Content-Type", "X-Requested-With"]
    )

    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def cors_origins(self) -> List[str]:
        """Converte a string de origens CORS para lista."""
        return [origin.strip() for origin in self.cors_origins_raw.split(",") if origin.strip()]


settings = Settings()
