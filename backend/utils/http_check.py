"""
Verificação HTTP robusta para detecção de phishing.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


def check_http(url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, Optional[int], dict]:
    """
    Faz verificação HTTP.

    Returns:
        (ok, status_code, details)

    details:
        {
            "final_url": str,
            "redirected": bool,
            "https": bool,
            "cert_valid": bool
        }
    """

    if not url:
        return False, None, {}

    details = {
        "final_url": None,
        "redirected": False,
        "https": url.startswith("https"),
        "cert_valid": True,
    }

    try:
        # 🔴 1. Tenta HEAD primeiro (mais rápido)
        try:
            resp = requests.head(
                url,
                timeout=timeout,
                headers=DEFAULT_HEADERS,
                allow_redirects=True,
                verify=True,
            )
        except Exception:
            # fallback para GET
            resp = requests.get(
                url,
                timeout=timeout,
                headers=DEFAULT_HEADERS,
                allow_redirects=True,
                verify=True,
            )

        details["final_url"] = resp.url
        details["redirected"] = resp.url != url

        ok = resp.status_code < 400

        return ok, resp.status_code, details

    # 🔴 Certificado inválido
    except requests.exceptions.SSLError:
        logger.warning("SSL inválido para %s", url)

        try:
            # tenta novamente sem verificação
            resp = requests.get(
                url,
                timeout=timeout,
                headers=DEFAULT_HEADERS,
                allow_redirects=True,
                verify=False,
            )

            details["cert_valid"] = False
            details["final_url"] = resp.url
            details["redirected"] = resp.url != url

            ok = resp.status_code < 400

            return ok, resp.status_code, details

        except Exception:
            return False, None, details

    except requests.exceptions.Timeout:
        logger.warning("Timeout HTTP para %s", url)
        return False, None, details

    except requests.exceptions.ConnectionError:
        logger.warning("Erro de conexão HTTP para %s", url)
        return False, None, details

    except Exception as exc:
        logger.warning("Erro HTTP inesperado para %s: %s", url, exc)
        return False, None, details
    

    