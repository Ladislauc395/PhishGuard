"""
backend/services/orchestrator.py
──────────────────────────────────
Orquestrador v12 — integra motor híbrido para análise de email.

CORRECÇÃO v12 (Bug 1):
  - orchestrate_url(): REMOVIDO o shortcut que devolvia resultado imediatamente
    quando local_score < 10. As APIs externas (VirusTotal + Google Safe Browsing)
    são SEMPRE chamadas, independentemente do score local.

ARQUITECTURA v12:
  - orchestrate_email(): delega para hybrid_analyzer.hybrid_analyze_email()
  - quick_local_analysis(): mantido para compatibilidade e uso interno
  - orchestrate_url(): chama SEMPRE VT + GSB (sem shortcut)
  - orchestrate_sms(): mantido para análise de SMS
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Optional
from urllib.parse import urlparse

from backend.services.ml_classifier import classify_with_groq
from backend.services.external_apis import (
    check_safe_browsing,
    check_virustotal,
)
from backend.services.dns_check import check_spf_dkim

logger = logging.getLogger(__name__)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")

# ─── Cache simples com TTL ────────────────────────────────────────
_url_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 300


def _cache_get(url: str) -> Optional[dict]:
    entry = _url_cache.get(url)
    if entry and (time.monotonic() - entry[0]) < _CACHE_TTL:
        return entry[1]
    return None


def _cache_set(url: str, result: dict) -> None:
    _url_cache[url] = (time.monotonic(), result)


def _safe_dict(x, default_key="error") -> dict:
    if isinstance(x, dict):
        return x
    return {default_key: f"invalid_type_{type(x).__name__}"}


# ─── Keywords PT/Angola ────────────────────────────────────────────

_PT_PHISHING_HIGH = [
    "clique aqui para validar", "validar a sua conta", "verificar a sua conta",
    "confirme os seus dados", "confirme seus dados", "confirmar os seus dados",
    "acesso suspenso", "conta bloqueada", "conta será bloqueada",
    "conta será suspensa", "palavra-passe expirada", "senha expirada",
    "actualizar os seus dados", "atualizar dados bancários", "dados de acesso",
    "introduza o seu pin", "introduza a sua senha", "verificação obrigatória",
    "evitar o bloqueio", "clique no link abaixo", "clicando no link abaixo",
    "clicando no link", "link expirado", "reactivação de conta",
    "nova tentativa de acesso", "login não autorizado", "confirmar identidade",
    "desbloquear conta", "proteger a sua conta", "acção requerida",
    "ação requerida", "responda imediatamente", "suspensão de conta",
    "identificamos atividade suspeita", "atividade suspeita na sua conta",
    "atividade suspeita detectada", "evitar o bloqueio imediato",
    "suspensa permanentemente",
]

_PT_PHISHING_MED = [
    "urgente", "acção necessária", "ação necessária", "último aviso",
    "prazo de 24 horas", "transferência pendente", "ganhou um prémio",
    "parabéns, foi seleccionado", "reembolso disponível", "oferta exclusiva",
    "acesso restrito", "conta limitada", "verificação pendente",
    "serviço suspenso", "actualização necessária", "atualização necessária",
]

_PT_CREDENTIAL_WORDS = [
    "pin", "senha", "password", "palavra-passe", "código de acesso",
    "iban", "número de conta", "cartão de débito", "cvv",
    "número do cartão", "token", "código de verificação",
    "código de segurança", "dados bancários", "credenciais",
]

_PT_URGENCY_WORDS = [
    "urgente", "imediato", "imediatamente", "agora mesmo",
    "24 horas", "48 horas", "prazo", "expira", "expirado", "expirada",
    "último aviso", "aviso final", "bloqueado", "bloqueada", "bloqueio",
    "suspenso", "suspensa", "suspensão", "acção necessária", "ação necessária",
    "não ignore", "importante", "crítico", "alerta",
    "permanentemente", "definitivamente",
]

_PROMO_WORDS = [
    "sorteio", "campanha", "promoção", "promocao", "concurso",
    "oferta especial", "desconto", "feliz aniversário", "celebração",
    "vencedor do", "felicitamos", "parabéns", "ganhou", "prémio",
]


def _score_pt_phishing(text: str) -> tuple[int, list[str]]:
    t = (text or "").lower()
    score = 0
    reasons: list[str] = []
    is_promo = any(w in t for w in _PROMO_WORDS)

    high_found = [kw for kw in _PT_PHISHING_HIGH if kw in t]
    for kw in high_found:
        score += 18
        reasons.append(f"Padrão de phishing detectado: «{kw}»")

    med_found = [kw for kw in _PT_PHISHING_MED if kw in t]
    if len(med_found) >= 2:
        score += 10 * len(med_found)
        for kw in med_found:
            reasons.append(f"Sinal de suspeita: «{kw}»")

    urgency_found = [w for w in _PT_URGENCY_WORDS if w in t]
    if len(urgency_found) >= 2:
        score += 15
        reasons.append(f"Linguagem de urgência: {', '.join(urgency_found[:3])}")

    cred_found = [kw for kw in _PT_CREDENTIAL_WORDS if kw in t]
    nif_suspicious = (
        "nif" in t
        and (urgency_found or high_found)
        and ("http" in t or re.search(r"bit\.ly|tinyurl|goo\.gl", t))
    )
    if nif_suspicious:
        cred_found.append("nif")

    if cred_found:
        if med_found or high_found or urgency_found:
            score += 30
            reasons.append(f"Pedido de dados sensíveis: {', '.join(cred_found[:3])}")
        else:
            score += 10

    if re.search(r"clique\s+(?:aqui|no\s+link|para\s+aceder)", t):
        score += 12
        reasons.append("Link com texto âncora suspeito")

    if is_promo and not cred_found and score < 30:
        score = 0
        reasons = []

    return score, reasons


# ─── Análise local de URL ──────────────────────────────────────────

_URL_BANKING_WORDS = {
    "banco", "bank", "seguro", "verificacao", "verificação", "confirmar",
    "validar", "login", "acesso", "conta", "account", "secure", "verify",
    "update", "payment", "banking", "confirm", "support", "alert",
}

_URL_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".pw", ".cam", ".icu", ".surf", ".monster",
    ".live", ".online", ".site", ".website", ".press",
    ".space", ".fun", ".host", ".shop", ".store",
}

_URL_SUSPICIOUS_PARAMS = {
    "token=", "confirmar", "validar", "conta=", "account=",
    "verify=", "redirect=", "login=", "password=", "senha=",
}


def _local_url_suspicion(url: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()
        path   = (parsed.path or "").lower()
        query  = (parsed.query or "").lower()
    except Exception:
        return 0, []

    if not domain:
        return 0, []

    base = domain.split(".")[0] if "." in domain else domain
    banking_in_domain = [w for w in _URL_BANKING_WORDS if w in base]
    if len(banking_in_domain) >= 2:
        score += 35
        reasons.append("Link malicioso detectado")
    elif len(banking_in_domain) == 1:
        score += 15
        reasons.append("Link suspeito detectado")

    params_found = [p for p in _URL_SUSPICIOUS_PARAMS if p in query]
    if params_found:
        score += 10
        reasons.append("Link suspeito detectado")

    if base.count("-") >= 2:
        score += 15
        reasons.append("Link suspeito detectado")

    for tld in _URL_SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            reasons.append("Link suspeito detectado")
            break

    if len(domain) > 30:
        score += 10

    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 30
        reasons.append("Link malicioso detectado")

    if "@" in url.split("?")[0]:
        score += 35
        reasons.append("Link malicioso detectado")

    return score, reasons


# ─── Helpers de detecção (remetente, marca, etc.) ─────────────────

_KNOWN_BRANDS = {
    "bai": "bai.ao", "bfa": "bfa.ao", "bic": "bic.ao", "bpc": "bpc.ao",
    "unitel": "unitel.ao", "movicel": "movicel.ao", "africell": "africell.ao",
    "multicaixa": "multicaixa.ao", "emis": "emis.ao",
    "netflix": "netflix.com", "paypal": "paypal.com",
    "google": "google.com", "microsoft": "microsoft.com",
    "amazon": "amazon.com", "facebook": "facebook.com",
    "dhl": "dhl.com", "fedex": "fedex.com",
}

_LEGIT_SENDING_DOMAINS = {
    "google.com", "googlemail.com", "gmail.com",
    "microsoft.com", "outlook.com", "hotmail.com",
    "yahoo.com", "amazon.com", "facebook.com",
    "unitel.ao", "movicel.ao", "africell.ao",
    "bai.ao", "bfa.ao", "bic.ao", "bpc.ao",
    "emis.ao", "multicaixa.ao",
}

_DISPLAY_SPOOF_BRANDS = list(_KNOWN_BRANDS.keys())


def _sender_is_legit(sender: str) -> bool:
    if not sender:
        return False
    s = sender.lower()
    return any(legit in s for legit in _LEGIT_SENDING_DOMAINS)


def _check_display_name_spoofing(sender: str) -> tuple[bool, str]:
    if not sender:
        return False, ""
    s = sender.lower()
    at_pos = s.find("@")
    if at_pos < 0:
        return False, ""
    display = s[:at_pos]
    domain  = s[at_pos + 1:]
    for brand in _DISPLAY_SPOOF_BRANDS:
        if brand in display and _KNOWN_BRANDS.get(brand, "") not in domain:
            return True, brand
    return False, ""


def _check_typosquatting(domain: str) -> tuple[bool, str, str]:
    if not domain:
        return False, "", ""
    d = domain.lower()
    for brand, legit in _KNOWN_BRANDS.items():
        legit_base = legit.split(".")[0]
        if brand in d and legit not in d:
            return True, brand, legit
    return False, "", ""


def _check_suspicious_domain(domain: str) -> tuple[int, list[str]]:
    if not domain:
        return 0, []
    score = 0
    reasons: list[str] = []
    suspicious_tlds = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 20
            reasons.append(f"TLD suspeito: {tld}")
            break
    if domain.count("-") >= 3:
        score += 15
        reasons.append("Domínio com muitos hífens")
    if len(domain) > 40:
        score += 10
        reasons.append("Domínio muito longo")
    return score, reasons


def _sender_impersonation_check(sender: str, content: str) -> tuple[int, list[str]]:
    if not sender or not content:
        return 0, []
    s = sender.lower()
    c = content.lower()
    score = 0
    reasons: list[str] = []
    for brand in _DISPLAY_SPOOF_BRANDS:
        if brand in c and brand not in s:
            legit = _KNOWN_BRANDS.get(brand, "")
            if legit and legit not in s:
                score += 25
                reasons.append(f"Email menciona «{brand}» mas não vem do domínio oficial ({legit})")
                break
    return score, reasons


def _detect_brand(content: str) -> str:
    c = content.lower()
    for brand in _DISPLAY_SPOOF_BRANDS:
        if brand in c:
            return brand
    return ""


def quick_local_analysis(sender: str, headers: str, body: str) -> dict:
    content = f"{sender} {headers} {body}"
    domain  = sender.split("@")[-1].lower().strip(">") if "@" in sender else ""
    urls_in_body = re.findall(r"https?://[^\s<>\"')\]]+", content)
    is_legit = _sender_is_legit(sender)

    score = 0
    reasons: list[str] = []

    pt_score, pt_reasons = _score_pt_phishing(content)

    max_url_score = 0
    url_reasons_agg: list[str] = []
    for url in urls_in_body[:5]:
        u_score, u_reasons = _local_url_suspicion(url)
        if u_score > max_url_score:
            max_url_score = u_score
        url_reasons_agg.extend(u_reasons)

    is_spoofed, spoofed_brand = _check_display_name_spoofing(sender)
    is_typosquat, typosquat_brand, legit_domain = _check_typosquatting(domain)
    domain_score, domain_reasons = _check_suspicious_domain(domain)
    impersonation_score, impersonation_reasons = _sender_impersonation_check(sender, content)

    if pt_score > 0:
        if is_legit:
            score += pt_score // 4
        else:
            score += pt_score
        reasons.extend(pt_reasons)

    if max_url_score >= 30:
        score += max_url_score
        reasons.extend(list(dict.fromkeys(url_reasons_agg)))
    elif max_url_score > 0 and not is_legit:
        score += max_url_score // 2

    if is_spoofed:
        score += 35
        reasons.append(f"O display name imita «{spoofed_brand}» mas o email não vem desse domínio")

    if is_typosquat:
        score += 40
        reasons.append(f"Domínio «{domain}» imita «{typosquat_brand}» ({legit_domain})")

    score += domain_score
    reasons.extend(domain_reasons)

    if impersonation_score > 0:
        score += impersonation_score
        reasons.extend(impersonation_reasons)

    if max_url_score >= 20 and pt_score >= 18 and not is_legit:
        score = max(score, 70)
        if "URL suspeita combinada com texto de phishing" not in reasons:
            reasons.append("URL suspeita combinada com texto de phishing")

    if impersonation_score > 0 and max_url_score >= 15:
        score = max(score, 75)

    if is_legit and not is_typosquat and not is_spoofed:
        if score < 50:
            score = min(score, 25)

    score = min(100, max(0, score))
    verdict = "NÃO SEGURO" if score >= 60 else ("SUSPEITO" if score >= 30 else "SEGURO")

    return {
        "score":        score,
        "verdict":      verdict,
        "reasons":      reasons,
        "sender":       sender,
        "domain":       domain,
        "is_legit":     is_legit,
        "is_typosquat": is_typosquat,
        "is_spoofed":   is_spoofed,
        "urls_count":   len(urls_in_body),
    }


# ─── URL analysis (standalone) ────────────────────────────────────

async def orchestrate_url(url: str) -> dict:
    """
    Análise de URL individual.

    CORRECÇÃO v12 (Bug 1):
    - REMOVIDO o shortcut 'if local_score < 10: return result' que impedia
      as APIs externas (VirusTotal + GSB) de correr para sites aparentemente
      seguros localmente.
    - As APIs externas são SEMPRE chamadas, garantindo que sites maliciosos
      com domínios limpos localmente sejam detectados pelas blacklists.
    """
    cached = _cache_get(url)
    if cached:
        return {**cached, "cached": True}

    local_score, local_reasons = _local_url_suspicion(url)

    # ── CORRECÇÃO: não há mais shortcut aqui — as APIs correm SEMPRE ──
    try:
        vt_task  = check_virustotal(url)
        gsb_task = check_safe_browsing(url)
        vt, gsb  = await asyncio.wait_for(
            asyncio.gather(vt_task, gsb_task, return_exceptions=True),
            timeout=8.0,
        )

        ext_score = local_score
        if isinstance(vt, dict) and (vt.get("malicious", 0) >= 3 or vt.get("suspicious", 0) >= 3):
            ext_score = max(ext_score, 80)
            local_reasons.append(f"VirusTotal: {vt.get('malicious', 0)} motores detectaram ameaça")
        elif isinstance(vt, dict) and vt.get("malicious", 0) >= 1:
            ext_score = max(ext_score, max(local_score, 40))
            local_reasons.append("VirusTotal: detecção positiva")

        if isinstance(gsb, dict) and gsb.get("threat"):
            ext_score = max(ext_score, 85)
            local_reasons.append("Google Safe Browsing: ameaça detectada")

        local_score = ext_score

    except (asyncio.TimeoutError, Exception) as e:
        logger.info("APIs timeout/falha para URL %s: %s", url, type(e).__name__)

    score   = min(100, local_score)
    verdict = "NÃO SEGURO" if score >= 60 else ("SUSPEITO" if score >= 30 else "SEGURO")
    result  = {
        "score":   score,
        "verdict": verdict,
        "url":     url,
        "reasons": list(dict.fromkeys(local_reasons)),
    }
    _cache_set(url, result)
    return result


# ─── SMS ──────────────────────────────────────────────────────────

async def orchestrate_sms(body: str, phone: str | None = None) -> dict:
    body = body or ""
    ml   = _safe_dict(await classify_with_groq(body, "sms"))
    pt_score, pt_reasons = _score_pt_phishing(body)
    urls = URL_RE.findall(body)
    url_details = []
    for u in urls[:3]:
        try:
            url_result = await orchestrate_url(u)
            url_details.append({
                "url":     u,
                "score":   url_result.get("score", 0),
                "verdict": url_result.get("verdict", "SEGURO"),
                "reasons": url_result.get("reasons", []),
            })
        except Exception as e:
            url_details.append({"url": u, "score": 0, "error": str(e)})
    url_component = max([u["score"] for u in url_details], default=0)
    ml_score      = int(ml.get("ml_score", 0))
    heuristic_base = max(ml_score, pt_score)
    final = min(100, int(heuristic_base * 0.6 + url_component * 0.4))
    verdict = "NÃO SEGURO" if final >= 60 else ("SUSPEITO" if final >= 30 else "SEGURO")
    reasons = []
    if ml.get("reasoning"):
        reasons.append(f"IA: {ml['reasoning']}")
    reasons.extend(pt_reasons)
    return {
        "score": final, "verdict": verdict, "ml": ml,
        "phone": phone, "urls_analyzed": url_details, "reasons": reasons,
    }


# ─── Email (delega para hybrid_analyzer) ──────────────────────────

async def orchestrate_email(sender: str, headers: str, body: str | None) -> dict:
    """
    Análise holística de email — v12.
    Delega para hybrid_analyzer.hybrid_analyze_email() com fallback
    para análise local se o motor híbrido falhar.
    """
    try:
        from backend.services.hybrid_analyzer import hybrid_analyze_email
        result = await asyncio.wait_for(
            hybrid_analyze_email(
                sender=sender,
                headers=headers or "",
                body=body or "",
                run_external_apis=True,
                timeout_total=55.0,
            ),
            timeout=58.0,
        )
        return {
            "score":          result.score,
            "verdict":        result.verdict,
            "ml":             result.ml,
            "dns":            result.dns,
            "brand_check":    {"is_official": not result.is_typosquat and not result.is_spoofed},
            "sender":         result.sender,
            "domain":         result.domain,
            "brand_detected": result.brand_detected,
            "is_typosquat":   result.is_typosquat,
            "typosquat_brand": "",
            "is_spoofed":     result.is_spoofed,
            "spoofed_brand":  "",
            "urls_checked":   result.urls_checked,
            "reasons":        result.reasons,
            "spf_pass":       result.spf_pass,
            "dkim_pass":      result.dkim_pass,
            "dmarc_pass":     result.dmarc_pass,
            "yara_matched":   result.yara_matched,
            "ner_brands":     result.ner_brands,
            "layers":         result.layers,
        }
    except Exception as e:
        logger.warning("hybrid_analyzer falhou (%s) — usando quick_local_analysis", e)
        local = quick_local_analysis(sender or "", headers or "", body or "")
        domain = local.get("domain", "")
        return {
            "score":          local["score"],
            "verdict":        local["verdict"],
            "ml":             {},
            "dns":            {},
            "brand_check":    {"is_official": local.get("is_legit", False)},
            "sender":         sender or "",
            "domain":         domain,
            "brand_detected": _detect_brand((body or "") + (headers or "")),
            "is_typosquat":   local.get("is_typosquat", False),
            "typosquat_brand": "",
            "is_spoofed":     local.get("is_spoofed", False),
            "spoofed_brand":  "",
            "urls_checked":   [],
            "reasons":        local["reasons"],
            "spf_pass":       True,
            "dkim_pass":      True,
            "dmarc_pass":     True,
            "yara_matched":   [],
            "ner_brands":     [],
            "layers":         {"fallback": "quick_local_analysis"},
        }