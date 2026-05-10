"""
backend/services/email_analyzer.py
────────────────────────────────────
Analisador de e-mails para detecção de phishing.

CORRECÇÕES v15:
- Análise feita no ASSUNTO e no CORPO do email.
- APIs externas com fallback gracioso (nunca crasham o sistema).
- asyncio.get_running_loop() em vez do deprecado get_event_loop().
- Palavras-chave de phishing/urgência aplicadas ao assunto + corpo.
- Detecção de urgência no assunto (pontuação extra).
- Detecção de emojis de alerta no assunto.
- Score de assunto suspeito separado e auditável.
- Todas as importações de módulos internos com fallback.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
from email.parser import Parser
from email.utils import parseaddr
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

LINK_REGEX = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "cutt.ly"]

# ─── Palavras-chave de phishing (assunto + corpo) ─────────────────

_PHISHING_KEYWORDS = [
    # Credenciais
    r"\bpin\b", r"\bsenha\b", r"\bpassword\b", r"\bcvv\b", r"\biban\b",
    "codigo de acesso", "numero de conta", "numero do cartao",
    "dados bancarios", "dados bancários",
    # Urgência
    r"urgent[ei]?", "urgente", "imediato", "último aviso", "ultimo aviso",
    "24 horas", "48 horas", "conta bloqueada", "acesso suspenso",
    "suspensão de conta", "suspensao de conta", "senha expirada",
    "palavra-passe expirada", "atividade suspeita", "login não autorizado",
    "login nao autorizado", "reativação de conta", "reativacao de conta",
    # Acção
    "clique aqui", "aceda já", "aceda ja", "acesse agora",
    "verificar a sua conta", "confirme os seus dados", "valide a sua conta",
    # Angola específico
    "multicaixa", "bai directo", "bai net", "bfa net",
    "conta suspensa", "bloqueio imediato",
]

_PHISHING_KW_RE = re.compile(
    "|".join(_PHISHING_KEYWORDS),
    re.IGNORECASE | re.UNICODE,
)

# Emojis de urgência/alerta no assunto
_ALERT_EMOJI_RE = re.compile(r"[🚨⚠️🔴🔒❗❕‼️🛑🚫]")

# ─── Acesso às configurações ──────────────────────────────────────

def _get_settings():
    try:
        from backend.core.config import settings
        return settings
    except Exception:
        return None


def _vt_key() -> Optional[str]:
    s = _get_settings()
    return getattr(s, "VIRUSTOTAL_API_KEY", None) or os.getenv("VIRUSTOTAL_API_KEY")


def _urlscan_key() -> Optional[str]:
    s = _get_settings()
    return getattr(s, "URLSCAN_API_KEY", None) or os.getenv("URLSCAN_API_KEY")


def _safe_browsing_key() -> Optional[str]:
    s = _get_settings()
    return (
        getattr(s, "GOOGLE_SAFE_BROWSING_API_KEY", None)
        or os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    )


def _abuseipdb_key() -> Optional[str]:
    s = _get_settings()
    return getattr(s, "ABUSEIPDB_API_KEY", None) or os.getenv("ABUSEIPDB_API_KEY")


# ─── Parsing de cabeçalhos ────────────────────────────────────────

def parse_headers(raw_headers: str) -> Dict[str, str]:
    parser = Parser()
    msg = parser.parsestr(raw_headers or "")
    return {k.lower(): msg.get(k, "") for k in msg.keys()}


def extract_subject(raw_headers: str) -> str:
    """Extrai o assunto do email a partir dos cabeçalhos."""
    parsed = parse_headers(raw_headers)
    return parsed.get("subject", "")


def _has_pass(auth: str, key: str) -> bool:
    return f"{key}=pass" in auth


def _has_fail(auth: str, key: str) -> bool:
    return any(x in auth for x in [f"{key}=fail", f"{key}=softfail", f"{key}=none"])


def analyze_auth(raw_headers: str) -> Tuple[bool, bool, bool]:
    parsed       = parse_headers(raw_headers)
    auth         = parsed.get("authentication-results", "").lower()
    received_spf = parsed.get("received-spf", "").lower()

    spf_pass = _has_pass(auth, "spf") or (
        "pass" in received_spf and "fail" not in received_spf
    )
    if _has_fail(auth, "spf"):
        spf_pass = False

    dkim_pass = _has_pass(auth, "dkim")
    if _has_fail(auth, "dkim"):
        dkim_pass = False

    dmarc_pass = _has_pass(auth, "dmarc")
    return spf_pass, dkim_pass, dmarc_pass


def _extract_sender_domain(raw_headers: str) -> str:
    parsed      = parse_headers(raw_headers)
    from_header = parsed.get("from", "")
    email_addr  = parseaddr(from_header)[1]
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower()
    return ""


def _validate_sender_domain(domain: str) -> bool:
    if not domain:
        return False
    try:
        from backend.services.dns_check import check_dns
        resolves, _ips, _err = check_dns(domain)
        return resolves
    except Exception:
        # Fallback: tentar resolver via socket
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False


LEGITIMATE_THIRD_PARTY = {
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "office.com", "office365.com",
    "mailchimp.com", "sendgrid.net", "amazonses.com",
    "mandrillapp.com", "sparkpostmail.com", "mailgun.org",
    "facebook.com", "twitter.com", "linkedin.com",
    "youtube.com", "instagram.com",
}


def _is_legitimate_third_party(url_domain: str) -> bool:
    return any(legit in url_domain for legit in LEGITIMATE_THIRD_PARTY)


def _check_domain_mismatch(
    sender_domain: str, urls: List[str]
) -> Tuple[bool, List[str]]:
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

    non_sender = [
        u for u in urls
        if sender_domain not in urlparse(u).netloc.lower()
    ]
    return (len(mismatched) >= 2 and len(mismatched) == len(non_sender)), mismatched


# ─── Análise de palavras-chave (assunto + corpo) ──────────────────

def _analyze_keywords(subject: str, body: str) -> Tuple[int, List[str]]:
    """
    Detecta palavras-chave de phishing no assunto e no corpo.
    Devolve (score_extra, lista_de_motivos).
    """
    score = 0
    reasons: List[str] = []

    # --- Assunto ---
    if subject:
        subject_matches = _PHISHING_KW_RE.findall(subject)
        if subject_matches:
            unique = list(dict.fromkeys(m.lower() for m in subject_matches))
            score += min(30, len(unique) * 10)
            reasons.append(
                f"Palavras-chave suspeitas no assunto: {', '.join(unique[:5])}"
            )

        # Emojis de alerta no assunto
        alert_emojis = _ALERT_EMOJI_RE.findall(subject)
        if alert_emojis:
            score += 10
            reasons.append(
                f"Emojis de urgência no assunto: {''.join(set(alert_emojis))}"
            )

        # Assunto em maiúsculas (urgência simulada)
        words = subject.split()
        caps_words = [w for w in words if len(w) >= 4 and w.isupper()]
        if len(caps_words) >= 2:
            score += 10
            reasons.append("Assunto com múltiplas palavras em maiúsculas (urgência artificial)")

    # --- Corpo ---
    if body:
        body_matches = _PHISHING_KW_RE.findall(body)
        if body_matches:
            unique = list(dict.fromkeys(m.lower() for m in body_matches))
            # Mais palavras = mais suspeito, mas com tecto
            score += min(25, len(unique) * 5)
            if len(unique) >= 3:
                reasons.append(
                    f"Múltiplas palavras-chave de phishing no corpo ({len(unique)}): "
                    f"{', '.join(unique[:5])}"
                )
            else:
                reasons.append(
                    f"Palavras-chave suspeitas no corpo: {', '.join(unique[:5])}"
                )

    return min(score, 50), reasons


# ─── APIs externas (VirusTotal, PhishTank, URLScan, AbuseIPDB, DNSBL) ─

async def _check_virustotal(url: str) -> Dict:
    api_key = _vt_key()
    if not api_key:
        return {"score": 0, "malicious": 0, "suspicious": 0, "source": "virustotal_skip"}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key},
            )
            if r.status_code == 404:
                r2 = await c.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": api_key},
                    data={"url": url},
                )
                if r2.status_code in (200, 201):
                    analysis_id = r2.json().get("data", {}).get("id", "")
                    if analysis_id:
                        await asyncio.sleep(3)
                        r3 = await c.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers={"x-apikey": api_key},
                        )
                        if r3.status_code == 200:
                            stats = (
                                r3.json()
                                .get("data", {})
                                .get("attributes", {})
                                .get("stats", {})
                            )
                            malicious  = stats.get("malicious", 0)
                            suspicious = stats.get("suspicious", 0)
                            score = min(100, (malicious * 15) + (suspicious * 8))
                            return {
                                "score": score,
                                "malicious": malicious,
                                "suspicious": suspicious,
                                "source": "virustotal",
                            }
                return {"score": 0, "malicious": 0, "suspicious": 0, "source": "virustotal"}

            if r.status_code == 429:
                logger.warning("VirusTotal: limite de API atingido (429)")
                return {"score": 0, "malicious": 0, "suspicious": 0, "source": "virustotal_ratelimit"}

            if r.status_code != 200:
                return {"score": 0, "malicious": 0, "suspicious": 0, "source": "virustotal_error"}

            data  = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            score = min(100, (malicious * 15) + (suspicious * 8))
            return {
                "score": score,
                "malicious": malicious,
                "suspicious": suspicious,
                "source": "virustotal",
            }
    except httpx.TimeoutException:
        return {"score": 0, "malicious": 0, "suspicious": 0, "source": "virustotal_timeout"}
    except Exception as exc:
        logger.debug("VirusTotal falhou para %s: %s", url[:60], exc)
        return {"score": 0, "malicious": 0, "suspicious": 0, "source": "virustotal_error"}


async def _check_phishtank(url: str) -> Dict:
    try:
        s = _get_settings()
        phishtank_key = (
            getattr(s, "PHISHTANK_API_KEY", None) or os.getenv("PHISHTANK_API_KEY", "")
        )
        import urllib.parse
        encoded_url = urllib.parse.quote_plus(url)
        data: Dict = {"url": encoded_url, "format": "json"}
        if phishtank_key:
            data["app_key"] = phishtank_key

        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=data,
                headers={"User-Agent": "PhishGuard/2.0"},
            )
            if r.status_code != 200:
                return {"is_phishing": False, "score": 0, "source": "phishtank_error"}
            result = r.json().get("results", {})
            in_database = result.get("in_database", False)
            valid       = result.get("valid", False)
            if in_database and valid:
                return {"is_phishing": True, "score": 90, "source": "phishtank"}
            return {"is_phishing": False, "score": 0, "source": "phishtank"}
    except httpx.TimeoutException:
        return {"is_phishing": False, "score": 0, "source": "phishtank_timeout"}
    except Exception:
        return {"is_phishing": False, "score": 0, "source": "phishtank_error"}


async def _check_urlscan(url: str) -> Dict:
    api_key = _urlscan_key()
    if not api_key:
        return {"score": 0, "malicious": False, "source": "urlscan_skip"}
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    try:
        domain = urlparse(url).netloc
        async with httpx.AsyncClient(timeout=12) as c:
            search_r = await c.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 1},
                headers=headers,
            )
            if search_r.status_code == 200:
                results = search_r.json().get("results", [])
                if results:
                    verdict   = results[0].get("verdicts", {}).get("overall", {})
                    malicious = verdict.get("malicious", False)
                    score_pct = verdict.get("score", 0)
                    score = (
                        min(100, int(score_pct * 100))
                        if score_pct <= 1
                        else min(100, score_pct)
                    )
                    if malicious:
                        score = max(score, 70)
                    return {"score": score, "malicious": malicious, "source": "urlscan"}

            submit_r = await c.post(
                "https://urlscan.io/api/v1/scan/",
                json={"url": url, "visibility": "private"},
                headers=headers,
            )
            if submit_r.status_code in (200, 201):
                uuid = submit_r.json().get("uuid", "")
                if uuid:
                    await asyncio.sleep(8)
                    result_r = await c.get(
                        f"https://urlscan.io/api/v1/result/{uuid}/",
                        headers=headers,
                    )
                    if result_r.status_code == 200:
                        verdict   = result_r.json().get("verdicts", {}).get("overall", {})
                        malicious = verdict.get("malicious", False)
                        score_pct = verdict.get("score", 0)
                        score = (
                            min(100, int(score_pct * 100))
                            if score_pct <= 1
                            else min(100, score_pct)
                        )
                        if malicious:
                            score = max(score, 70)
                        return {"score": score, "malicious": malicious, "source": "urlscan"}

        return {"score": 0, "malicious": False, "source": "urlscan"}
    except httpx.TimeoutException:
        return {"score": 0, "malicious": False, "source": "urlscan_timeout"}
    except Exception:
        return {"score": 0, "malicious": False, "source": "urlscan_error"}


async def _check_safe_browsing(urls: List[str]) -> Dict[str, bool]:
    api_key = _safe_browsing_key()
    if not api_key or not urls:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json={
                    "client": {"clientId": "phishguard", "clientVersion": "2.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": u} for u in urls[:500]],
                    },
                },
            )
            if r.status_code != 200:
                return {}
            matches = r.json().get("matches", [])
            flagged = {m["threat"]["url"] for m in matches}
            return {u: True for u in flagged}
    except Exception:
        return {}


async def _check_abuseipdb(ip: str) -> Dict:
    api_key = _abuseipdb_key()
    if not api_key:
        return {"abuse_score": 0, "source": "abuseipdb_skip"}
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                return {
                    "abuse_score":   data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "source":        "abuseipdb",
                }
    except Exception:
        pass
    return {"abuse_score": 0, "source": "abuseipdb_error"}


def _check_dnsbl(domain: str) -> Dict:
    """Verifica domínio contra DNSBL zones (SURBL, Spamhaus, URIBL)."""
    zones = ["multi.surbl.org", "dbl.spamhaus.org", "uribl.com"]
    hits  = []
    for zone in zones:
        try:
            socket.gethostbyname(f"{domain}.{zone}")
            hits.append(zone)
        except socket.error:
            pass
    return {"flagged": bool(hits), "hits": hits, "source": "dnsbl"}


# ─── Análise de URL combinada (VirusTotal + PhishTank + URLScan) ──

async def _analyze_url_with_apis(url: str) -> Dict:
    results = await asyncio.gather(
        _check_virustotal(url),
        _check_phishtank(url),
        _check_urlscan(url),
        return_exceptions=True,
    )
    vt_result      = results[0] if not isinstance(results[0], Exception) else {}
    pt_result      = results[1] if not isinstance(results[1], Exception) else {}
    urlscan_result = results[2] if not isinstance(results[2], Exception) else {}

    vt_score      = vt_result.get("score", 0)
    pt_score      = pt_result.get("score", 0)
    urlscan_score = urlscan_result.get("score", 0)

    if pt_result.get("is_phishing"):
        combined_score = 95
    else:
        combined_score = max(vt_score, pt_score, urlscan_score)
        detections = sum([
            1 if vt_score >= 30 else 0,
            1 if pt_score >= 30 else 0,
            1 if urlscan_score >= 30 else 0,
        ])
        if detections >= 2:
            combined_score = min(100, combined_score + 15)

    sources = []
    if vt_result.get("malicious", 0) > 0:
        sources.append(f"virustotal({vt_result.get('malicious', 0)} motores)")
    if pt_result.get("is_phishing"):
        sources.append("phishtank")
    if urlscan_result.get("malicious"):
        sources.append("urlscan.io")

    classification = (
        "MALICIOSO" if combined_score >= 70
        else "SUSPEITO" if combined_score >= 40
        else "POTENCIALMENTE_SUSPEITO" if combined_score >= 20
        else "SEGURO"
    )

    return {
        "url":            url,
        "score":          combined_score,
        "classification": classification,
        "sources":        sources,
        "details": {
            "virustotal": vt_result,
            "phishtank":  pt_result,
            "urlscan":    urlscan_result,
        },
    }


# ─── Funções principais (síncrona e assíncrona) ───────────────────

def analyze_email(raw_headers: str, body: str | None = None) -> dict:
    """
    Wrapper síncrono para analyze_email_async.
    Compatível com contextos onde o event loop já está a correr.
    """
    try:
        try:
            loop = asyncio.get_running_loop()
            # Já existe um loop a correr → usar thread separada
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, analyze_email_async(raw_headers, body))
                return future.result(timeout=90)
        except RuntimeError:
            # Sem loop a correr → criar um novo
            return asyncio.run(analyze_email_async(raw_headers, body))
    except Exception as exc:
        logger.error("analyze_email síncrono falhou, usando fallback: %s", exc)
        return _analyze_email_sync_fallback(raw_headers, body)


async def analyze_email_async(raw_headers: str, body: str | None = None) -> dict:
    """
    Análise completa assíncrona: autenticação, assunto, corpo e URLs.
    """
    # Importação do scoring com fallback
    def _classify(s: int) -> str:
        try:
            from backend.services.scoring import classify_score
            return classify_score(s)
        except Exception:
            if s >= 70:
                return "NÃO SEGURO"
            if s >= 40:
                return "SUSPEITO"
            return "SEGURO"

    score = 0
    reasons: List[str] = []

    # ── Etapa 1: Extracção do assunto ────────────────────────────
    subject = extract_subject(raw_headers)

    # ── Etapa 2: Autenticação (SPF / DKIM / DMARC) ───────────────
    spf_pass, dkim_pass, dmarc_pass = analyze_auth(raw_headers)

    auth_penalty = 0
    if not spf_pass:
        auth_penalty += 15
        reasons.append("SPF falhou")
    if not dkim_pass:
        auth_penalty += 10
        reasons.append("DKIM não verificado")
    if not dmarc_pass:
        auth_penalty += 5
        reasons.append("DMARC falhou")
    if not spf_pass and not dkim_pass and not dmarc_pass:
        auth_penalty += 10
        reasons.insert(0, "auth_fail:SPF+DKIM+DMARC")
    score += auth_penalty

    # ── Etapa 3: Análise de palavras-chave (assunto + corpo) ──────
    kw_score, kw_reasons = _analyze_keywords(subject, body or "")
    score   += kw_score
    reasons += kw_reasons

    # ── Etapa 4: Extracção e análise de URLs ─────────────────────
    # Incluir assunto na busca de URLs
    content = f"{subject}\n{body or ''}\n{raw_headers}"
    urls    = list(set(LINK_REGEX.findall(content)))
    urls    = [u for u in urls if len(urlparse(u).netloc) > 3][:20]

    url_results: List[Dict] = []
    max_url_score = 0
    safe_browsing_flags: Dict[str, bool] = {}

    if urls:
        try:
            safe_browsing_flags = await asyncio.wait_for(
                _check_safe_browsing(urls), timeout=10.0
            )
        except Exception:
            pass

    # Filtrar URLs de terceiros legítimos antes do scan profundo
    urls_to_deep_scan = [
        u for u in urls
        if not _is_legitimate_third_party(urlparse(u).netloc.lower().lstrip("www."))
    ][:10]

    for url in urls_to_deep_scan:
        try:
            if safe_browsing_flags.get(url):
                result = {
                    "url":            url,
                    "score":          80,
                    "classification": "MALICIOSO",
                    "sources":        ["google_safe_browsing"],
                }
                url_results.append(result)
                score += 50
                reasons.append(f"google_safe_browsing: link malicioso ({url[:80]})")
                max_url_score = max(max_url_score, 80)
                continue

            is_shortener = any(s in url for s in SHORTENERS)
            if is_shortener:
                score += 20
                reasons.append(f"url_shortener:{url[:80]}")

            result = await asyncio.wait_for(
                _analyze_url_with_apis(url),
                timeout=25.0,
            )
            url_results.append(result)
            url_score = result["score"]
            if url_score > max_url_score:
                max_url_score = url_score
            if url_score >= 40:
                sources_str = (
                    ", ".join(result.get("sources", []))
                    or result.get("classification", "")
                )
                reasons.append(
                    f"suspicious_link:{url[:80]} "
                    f"(score={url_score}, fontes={sources_str})"
                )
        except asyncio.TimeoutError:
            url_results.append({"url": url, "score": 0, "classification": "TIMEOUT"})
        except Exception as exc:
            logger.warning("Erro ao analisar link %s: %s", url[:60], exc)

    # Pontuar baseado no URL mais suspeito encontrado
    if max_url_score >= 80:
        score += 60
    elif max_url_score >= 60:
        score += 45
    elif max_url_score >= 40:
        score += 30
    elif max_url_score >= 20:
        score += 15

    # ── Etapa 5: Domínio do remetente ────────────────────────────
    sender_domain = _extract_sender_domain(raw_headers)
    if sender_domain and not _validate_sender_domain(sender_domain):
        score += 30
        reasons.append(f"sender_domain_no_dns:{sender_domain}")

    # AbuseIPDB + DNSBL para o domínio do remetente
    if sender_domain and not _is_legitimate_third_party(sender_domain):
        try:
            ip: Optional[str] = None
            try:
                loop = asyncio.get_running_loop()
                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, sender_domain),
                    timeout=3.0,
                )
            except Exception:
                pass

            if ip:
                abuse_result = await asyncio.wait_for(
                    _check_abuseipdb(ip), timeout=5.0
                )
                abuse_score = abuse_result.get("abuse_score", 0)
                if abuse_score >= 80:
                    score += 30
                    reasons.append(
                        f"AbuseIPDB: IP do remetente com reputação muito má "
                        f"({abuse_score}/100)"
                    )
                elif abuse_score >= 50:
                    score += 15
                    reasons.append(f"AbuseIPDB: IP suspeito ({abuse_score}/100)")

            loop2 = asyncio.get_running_loop()
            dnsbl_result = await asyncio.wait_for(
                loop2.run_in_executor(None, _check_dnsbl, sender_domain),
                timeout=5.0,
            )
            if dnsbl_result.get("flagged"):
                hits = ", ".join(dnsbl_result["hits"])
                score += 25
                reasons.append(f"DNSBL: domínio listado em {hits}")

        except Exception as e:
            logger.debug("Erro nas verificações de domínio: %s", e)

    # ── Etapa 6: Domain mismatch ──────────────────────────────────
    if sender_domain and urls:
        mismatch, mismatch_urls = _check_domain_mismatch(sender_domain, urls)
        if mismatch:
            score += 30
            sample = mismatch_urls[0] if mismatch_urls else ""
            reasons.append(
                f"domain_mismatch:{sender_domain} vs {sample[:60]} "
                f"(+{len(mismatch_urls) - 1} outros)"
            )

    score = min(score, 100)
    classification = _classify(score)

    return {
        "score":          score,
        "classification": classification,
        "reasons":        reasons,
        "auth":           {"spf": spf_pass, "dkim": dkim_pass, "dmarc": dmarc_pass},
        "subject":        subject,
        "urls_found":     urls,
        "url_analysis":   url_results,
        "keyword_score":  kw_score,
    }


def _analyze_email_sync_fallback(raw_headers: str, body: str | None = None) -> dict:
    """Fallback síncrono sem APIs externas para quando o event loop falha."""
    def _classify(s: int) -> str:
        try:
            from backend.services.scoring import classify_score
            return classify_score(s)
        except Exception:
            if s >= 70:
                return "NÃO SEGURO"
            if s >= 40:
                return "SUSPEITO"
            return "SEGURO"

    score = 0
    reasons: List[str] = []

    subject = extract_subject(raw_headers)

    spf_pass, dkim_pass, dmarc_pass = analyze_auth(raw_headers)
    auth_penalty = 0
    if not spf_pass:
        auth_penalty += 15
        reasons.append("SPF falhou")
    if not dkim_pass:
        auth_penalty += 10
        reasons.append("DKIM falhou")
    if not dmarc_pass:
        auth_penalty += 5
        reasons.append("DMARC falhou")
    if not spf_pass and not dkim_pass and not dmarc_pass:
        auth_penalty += 10
    score += auth_penalty

    # Análise de palavras-chave (disponível no fallback)
    kw_score, kw_reasons = _analyze_keywords(subject, body or "")
    score   += kw_score
    reasons += kw_reasons

    content = f"{subject}\n{body or ''}\n{raw_headers}"
    urls    = list(set(LINK_REGEX.findall(content)))
    for url in urls:
        if any(s in url for s in SHORTENERS):
            score += 15
            reasons.append(f"url_shortener:{url[:80]}")

    sender_domain = _extract_sender_domain(raw_headers)
    if sender_domain and not _validate_sender_domain(sender_domain):
        score += 30
        reasons.append(f"sender_domain_no_dns:{sender_domain}")

    score = min(score, 100)
    return {
        "score":          score,
        "classification": _classify(score),
        "reasons":        reasons,
        "auth":           {"spf": spf_pass, "dkim": dkim_pass, "dmarc": dmarc_pass},
        "subject":        subject,
        "urls_found":     urls,
        "url_analysis":   [],
        "keyword_score":  kw_score,
    }
