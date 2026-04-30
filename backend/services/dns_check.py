"""
backend/services/dns_check.py
─────────────────────────────
Verificação DNS com dnspython.

CORRECÇÃO v2:
- Ficheiro movido/unificado em backend/services/ (era backend/utils/).
- check_dns() devolve sempre (bool, list[str], str|None) — 3 valores.
- check_spf_dkim() mantido para compatibilidade com orchestrator.py.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

resolver = dns.resolver.Resolver()
resolver.timeout = 3.0
resolver.lifetime = 3.0


def check_dns(domain: str) -> Tuple[bool, List[str], Optional[str]]:
    """
    Verifica se o domínio resolve via DNS.

    Returns:
        (resolves, ips, error)
    """
    if not domain:
        return False, [], "empty_domain"

    ips: List[str] = []

    try:
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(domain, record_type)
                ips.extend([str(r) for r in answers])
            except dns.resolver.NoAnswer:
                continue

        if ips:
            return True, ips, None

        return False, [], "no_records"

    except dns.resolver.NXDOMAIN:
        return False, [], "nxdomain"

    except dns.resolver.Timeout:
        return False, [], "timeout"

    except dns.exception.DNSException as exc:
        logger.warning("DNS erro para %s: %s", domain, exc)
        return False, [], "dns_error"

    except Exception as exc:
        logger.warning("Erro inesperado DNS %s: %s", domain, exc)
        return False, [], "unknown_error"


async def check_spf_dkim(domain: str) -> dict:
    """
    Realiza uma verificação real de registos SPF, DKIM e DMARC.
    Usado pelo orchestrator.py e hybrid_analyzer.py.
    """
    results = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "is_valid": False
    }

    try:
        # 1. Verificar SPF
        try:
            txt_records = resolver.resolve(domain, "TXT")
            for record in txt_records:
                record_text = str(record).strip('"')
                if record_text.startswith("v=spf1"):
                    results["spf"] = "pass"
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["spf"] = "fail"
        except Exception:
            results["spf"] = "fail"

        # 2. Verificar DMARC
        try:
            dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in dmarc_records:
                if "v=DMARC1" in str(record):
                    results["dmarc"] = "pass"
                    break
        except Exception:
            results["dmarc"] = "fail"

        # 3. Verificar DKIM (seletores comuns)
        selectors = ["default", "google", "k1", "mail", "dkim"]
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                resolver.resolve(dkim_domain, "TXT")
                results["dkim"] = "pass"
                break
            except Exception:
                continue

        if results["spf"] == "pass" or results["dkim"] == "pass":
            results["is_valid"] = True

        return results

    except Exception as e:
        logger.error("Erro na verificação SPF/DKIM para %s: %s", domain, e)
        return results
    