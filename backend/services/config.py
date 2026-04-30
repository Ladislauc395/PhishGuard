"""
backend/config.py
─────────────────
Carrega variáveis de ambiente do arquivo .env e expõe todas as
chaves de API usadas no PhishGuard.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Configuração básica de logging para ver o feedback no terminal
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Caminho para o .env (sobe dois níveis: de backend/core/ para a raiz)
# Se o arquivo estiver em backend/config.py, apenas um .parent resolve
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

# Carrega o .env. override=True garante que ele use o que está no arquivo
if _ENV_PATH.exists():
    load_dotenv(dotenv_path=_ENV_PATH, override=True)
    logger.info("Ficheiro .env carregado de: %s", _ENV_PATH)
else:
    logger.error("ERRO: Ficheiro .env não encontrado em: %s", _ENV_PATH)


@dataclass(frozen=True)
class _Settings:
    # ── Reputação (IDs corrigidos para bater com seu .env) ──────────
    VIRUSTOTAL_API_KEY: str = field(
        default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", "")
    )
    ABUSEIPDB_API_KEY: str = field(
        default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY", "")
    )
    # AJUSTE: No seu .env está 'URLSCAN_API'
    URLSCAN_API_KEY: str = field(
        default_factory=lambda: os.getenv("URLSCAN_API", "")
    )

    # ── Google APIs ────────────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY: str = field(
        default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    )
    GOOGLE_CUSTOM_SEARCH_API_KEY: str = field(
        default_factory=lambda: os.getenv("GOOGLE_CUSTOM_SEARCH_API_KEY", "")
    )
    GOOGLE_CUSTOM_SEARCH_ENGINE_ID: str = field(
        default_factory=lambda: os.getenv("GOOGLE_CUSTOM_SEARCH_ENGINE_ID", "")
    )

    # ── Gmail API OAuth2 ───────────────────────────────────────────
    GMAIL_CLIENT_ID: str = field(
        default_factory=lambda: os.getenv("GMAIL_CLIENT_ID", "")
    )
    GMAIL_CLIENT_SECRET: str = field(
        default_factory=lambda: os.getenv("GMAIL_CLIENT_SECRET", "")
    )
    GMAIL_REFRESH_TOKEN: str = field(
        default_factory=lambda: os.getenv("GMAIL_REFRESH_TOKEN", "")
    )
    GMAIL_REDIRECT_URI: str = field(
        default_factory=lambda: os.getenv("GMAIL_REDIRECT_URI", "http://localhost")
    )

    # ── SMS / Twilio ───────────────────────────────────────────────
    TWILIO_ACCOUNT_SID: str = field(
        default_factory=lambda: os.getenv("TWILIO_ACCOUNT_SID", "")
    )
    TWILIO_AUTH_TOKEN: str = field(
        default_factory=lambda: os.getenv("TWILIO_AUTH_TOKEN", "")
    )
    NUMVERIFY_API_KEY: str = field(
        default_factory=lambda: os.getenv("NUMVERIFY_API_KEY", "")
    )

    # ── Inteligência Artificial (Groq) ─────────────────────────────
    GROQ_API_KEY: str = field(
        default_factory=lambda: os.getenv("GROQ_API_KEY", "")
    )
    GROQ_MODEL: str = field(
        default_factory=lambda: os.getenv("GROQ_MODEL", "llama-3.3-70b-versatil")
    )

    def validate(self) -> None:
        """Loga quais chaves estão configuradas e quais estão faltando."""
        checks = {
            "VIRUSTOTAL_API_KEY":              self.VIRUSTOTAL_API_KEY,
            "ABUSEIPDB_API_KEY":               self.ABUSEIPDB_API_KEY,
            "URLSCAN_API_KEY":                 self.URLSCAN_API_KEY,
            "GOOGLE_SAFE_BROWSING_API_KEY":    self.GOOGLE_SAFE_BROWSING_API_KEY,
            "GOOGLE_CUSTOM_SEARCH_API_KEY":    self.GOOGLE_CUSTOM_SEARCH_API_KEY,
            "GOOGLE_CUSTOM_SEARCH_ENGINE_ID":  self.GOOGLE_CUSTOM_SEARCH_ENGINE_ID,
            "GMAIL_CLIENT_ID":                 self.GMAIL_CLIENT_ID,
            "GROQ_API_KEY":                    self.GROQ_API_KEY,
        }
        
        missing = [k for k, v in checks.items() if not v]
        
        print("\n--- STATUS DAS CONFIGURAÇÕES ---")
        for k, v in checks.items():
            status = "✅ OK" if v else "❌ AUSENTE"
            print(f"{k:40} {status}")
        
        if missing:
            print(f"\n⚠️  Atenção: {len(missing)} chaves em falta no .env\n")


# Instância singleton
settings = _Settings()

# Executa validação ao carregar o módulo para debugar no terminal do uvicorn
if __name__ == "__main__":
    settings.validate()
    