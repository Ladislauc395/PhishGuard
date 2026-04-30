"""Configuração central da aplicação (via variáveis de ambiente)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Base de dados ──────────────────────────────────────────
    DATABASE_URL: str = "postgresql+psycopg2://ladislau:1234@localhost:5432/phishguard"
    DEBUG: bool = False

    # ── JWT ────────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32"

    # ── Google OAuth (login com Google) ───────────────────────
    GOOGLE_CLIENT_ID: str = ""

    # ── Gmail Integration ──────────────────────────────────────
    GMAIL_CLIENT_ID: str = ""
    GMAIL_CLIENT_SECRET: str = ""
    GMAIL_REFRESH_TOKEN: str = ""
    GMAIL_REDIRECT_URI: str = "http://localhost"

    # ── VirusTotal ─────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""

    # ── AbuseIPDB ──────────────────────────────────────────────
    ABUSEIPDB_API_KEY: str = ""

    # ── URLScan.io ─────────────────────────────────────────────
    URLSCAN_API: str = ""           # nome no .env
    URLSCAN_API_KEY: str = ""       # alias usado no código

    def model_post_init(self, __context):
        # Garante que URLSCAN_API_KEY usa URLSCAN_API se não definido
        if self.URLSCAN_API and not self.URLSCAN_API_KEY:
            object.__setattr__(self, 'URLSCAN_API_KEY', self.URLSCAN_API)

    # ── Google Safe Browsing ───────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    # ── Google Custom Search ───────────────────────────────────
    GOOGLE_CUSTOM_SEARCH_API_KEY: str = ""
    GOOGLE_CUSTOM_SEARCH_ENGINE_ID: str = ""

    # ── Twilio (SMS) ───────────────────────────────────────────
    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""

    # ── Numverify (validação de números) ──────────────────────
    NUMVERIFY_API_KEY: str = ""

    # ── Groq (IA) ──────────────────────────────────────────────
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.1-70b-versatile"


settings = Settings()
