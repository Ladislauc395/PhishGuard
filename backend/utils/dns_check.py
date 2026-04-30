"""
backend/utils/dns_check.py
──────────────────────────
Shim de compatibilidade — re-exporta tudo de backend.services.dns_check.

PORQUÊ:
  O código original tinha check_dns() em dois lugares:
    - backend/utils/dns_check.py  (url_analyzer, email_analyzer importavam daqui)
    - backend/services/dns_check.py  (orchestrator importava daqui)

  CORRECÇÃO v2: a versão canónica fica em backend/services/dns_check.py.
  Este ficheiro garante retrocompatibilidade para qualquer import antigo.
"""

from backend.services.dns_check import check_dns, check_spf_dkim  # noqa: F401

__all__ = ["check_dns", "check_spf_dkim"]
