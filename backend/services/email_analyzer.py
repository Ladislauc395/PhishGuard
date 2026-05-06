"""
Analisador de e-mails para detecção de phishing.

CORRECÇÃO v2:
- check_dns importado de backend.services.dns_check (caminho correcto).
- _step_dns descompacta 3 valores: (resolves, ips, error).

Pipeline:
  1. Validar autenticação SPF/DKIM/DMARC
  2. Extrair e analisar links com analyze_url()
  3. Validar domínio do remetente (DNS + blacklists)
  4. Detectar spoofing e padrões suspeitos
"""

from __future__ import annotations

import logging
import re
from email.parser import Parser
from email.utils import parseaddr
from typing import Dict, List, Tuple
from urllib.parse import urlparse

# CORRECÇÃO: caminho correcto — ficheiro em backend/services/dns_check.py
from backend.services.dns_check import check_dns
from backend.services.scoring import classify_score

logger = logging.getLogger(__name__)

LINK_REGEX = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "cutt.ly"]


# ─── Parsing de headers ───────────────────────────────────────────

def parse_headers(raw_headers: str) -> Dict[str, str]:
    parser = Parser()
    msg = parser.parsestr(raw_headers or "")
    return {k.lower(): msg.get(k, "") for k in msg.keys()}


# ─── Autenticação ─────────────────────────────────────────────────

def _has_pass(auth: str, key: str) -> bool:
    return f"{key}=pass" in auth


def _has_fail(auth: str, key: str) -> bool:
    return any(x in auth for x in [f"{key}=fail", f"{key}=softfail", f"{key}=none"])


def analyze_auth(raw_headers: str) -> Tuple[bool, bool, bool]:
    parsed       = parse_headers(raw_headers)
    auth         = parsed.get("authentication-results", "").lower()
    received_spf = parsed.get("received-spf", "").lower()

    spf_pass = _has_pass(auth, "spf") or ("pass" in received_spf and "fail" not in received_spf)
    if _has_fail(auth, "spf"):
        spf_pass = False

    dkim_pass = _has_pass(auth, "dkim")
    if _has_fail(auth, "dkim"):
        dkim_pass = False

    dmarc_pass = _has_pass(auth, "dmarc")

    return spf_pass, dkim_pass, dmarc_pass


# ─── Remetente ────────────────────────────────────────────────────

def _extract_sender_domain(raw_headers: str) -> str:
    parsed      = parse_headers(raw_headers)
    from_header = parsed.get("from", "")

    email_addr = parseaddr(from_header)[1]
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower()

    return ""


def _validate_sender_domain(domain: str) -> bool:
    if not domain:
        return False

    # CORRECÇÃO: check_dns devolve (resolves, ips, error) — 3 valores
    resolves, _ips, _err = check_dns(domain)
    return resolves


# ─── Domain mismatch ─────────────────────────────────────────────

LEGITIMATE_THIRD_PARTY = {
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "office.com", "office365.com",
    "mailchimp.com", "sendgrid.net", "amazonses.com",
    "mandrillapp.com", "sparkpostmail.com", "mailgun.org",
    "unsubscribe", "list-unsubscribe",
    "facebook.com", "twitter.com", "linkedin.com",
    "youtube.com", "instagram.com",
}


def _is_legitimate_third_party(url_domain: str) -> bool:
    return any(legit in url_domain for legit in LEGITIMATE_THIRD_PARTY)


def _check_domain_mismatch(sender_domain: str, urls: List[str]) -> Tuple[bool, List[str]]:
    if not sender_domain or not urls:
        return False, []

    mismatched: List[str] = []

    for url in urls:
        try:
            parsed     = urlparse(url)
            url_domain = parsed.netloc.lower().lstrip("www.")

            if sender_domain in url_domain or url_domain in sender_domain:
                continue

            if _is_legitimate_third_party(url_domain):
                continue

            if any(s in url_domain for s in ["bit.ly", "tinyurl", "t.co"]):
                continue

            mismatched.append(url)

        except Exception:
            continue

    if len(mismatched) >= 2 and len(mismatched) == len([
        u for u in urls
        if sender_domain not in urlparse(u).netloc.lower()
    ]):
        return True, mismatched

    return False, []


# ─── Função principal ─────────────────────────────────────────────

def analyze_email(raw_headers: str, body: str | None = None) -> dict:
    from backend.services.url_analyzer import analyze_url

    score   = 0
    reasons: List[str] = []

    # ── Etapa 1: Autenticação SPF/DKIM/DMARC ──
    spf_pass, dkim_pass, dmarc_pass = analyze_auth(raw_headers)

    if not (spf_pass and dkim_pass and dmarc_pass):
        score += 40
        failed = []
        if not spf_pass:
            failed.append("SPF")
        if not dkim_pass:
            failed.append("DKIM")
        if not dmarc_pass:
            failed.append("DMARC")
        reasons.append(f"auth_fail:{'+'.join(failed)}")

    # ── Etapa 2: Links ──
    content = f"{body or ''}\n{raw_headers}"
    urls    = list(set(LINK_REGEX.findall(content)))

    url_results: List[Dict] = []
    max_url_score = 0

    for url in urls:
        try:
            result = analyze_url(url)
            url_results.append(result)

            if result["score"] > max_url_score:
                max_url_score = result["score"]

            if result["score"] >= 30:
                reasons.append(
                    f"suspicious_link:{url} "
                    f"(score={result['score']}, "
                    f"classification={result['classification']})"
                )

            if any(short in url for short in SHORTENERS):
                score += 20
                reasons.append(f"url_shortener:{url}")

        except Exception as exc:
            logger.warning("Erro ao analisar link %s: %s", url, exc)

    if max_url_score >= 80:
        score += 60
    elif max_url_score >= 50:
        score += 40
    elif max_url_score >= 30:
        score += 20

    # ── Etapa 3: Domínio do remetente ──
    sender_domain = _extract_sender_domain(raw_headers)

    if sender_domain and not _validate_sender_domain(sender_domain):
        score += 30
        reasons.append(f"sender_domain_no_dns:{sender_domain}")

    # ── Etapa 4: Domain mismatch ──
    if sender_domain and urls:
        mismatch, mismatch_urls = _check_domain_mismatch(sender_domain, urls)
        if mismatch:
            score += 30
            sample = mismatch_urls[0] if mismatch_urls else ""
            reasons.append(f"domain_mismatch:{sender_domain} vs {sample} (+{len(mismatch_urls)-1} outros)")

    score = min(score, 100)

    return {
        "score": score,
        "classification": classify_score(score),
        "reasons": reasons,
        "auth": {
            "spf":   spf_pass,
            "dkim":  dkim_pass,
            "dmarc": dmarc_pass,
        },
        "urls_found":    urls,
        "url_analysis":  url_results,
    }
