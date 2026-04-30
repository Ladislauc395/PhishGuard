"""
backend/services/hybrid_analyzer.py
─────────────────────────────────────────────────────────────────────────────
MOTOR DE ANÁLISE HÍBRIDA v11 — PhishGuard

Combina TODAS as camadas de detecção num pipeline resiliente:

  CAMADA 1 — Local/Offline (sempre disponível, <50ms):
    ├── Heurísticas PT/Angola (keywords, urgência, credenciais)
    ├── Análise estrutural de URLs (TLD, hifens, IP, @, encurtadores)
    ├── Display-name spoofing
    ├── Typosquatting (Levenshtein)
    └── Regras YARA (padrões de phishing compilados)

  CAMADA 2 — NLP/NER (spaCy, ~100ms):
    ├── Named Entity Recognition — detecta marcas/organizações no texto
    ├── BeautifulSoup — extrai texto limpo de HTML
    └── Score de conflito: entidade reconhecida ≠ domínio remetente

  CAMADA 3 — ML (Groq LLM, timeout 12s):
    ├── Análise semântica do texto completo
    └── Fallback para heurísticas se Groq indisponível

  CAMADA 4 — DNS/Auth (timeout 5s):
    ├── SPF, DKIM, DMARC
    └── Resolução DNS do remetente

  CAMADA 5 — APIs Externas em PARALELO (timeout 10s, apenas se score > 15):
    ├── VirusTotal (análise de URL)
    ├── Google Safe Browsing
    ├── URLScan.io (verificar resultado existente)
    ├── AbuseIPDB (IP do remetente)
    └── DNSBL (Spamhaus / SURBL / URIBL)

LÓGICA DE CONSENSO:
  - Score < 15 → retorna SEGURO imediatamente (sem APIs externas)
  - APIs externas: ≥2 positivas → score mínimo 80
  - Fallback em cascata: se camada N falhar → continuar com camada N-1
  - Timeout por camada → score parcial mantém-se, motivo registado

CORRECÇÕES v11:
  - Timeout por email: 60s com fallback parcial (não retorna SEGURO por timeout)
  - Emails de ESPs legítimos (Twilio, SendGrid, etc.) → score máx 25 se ML OK
  - YARA: regras integradas sem ficheiro externo (compiladas em memória)
  - NER: detecta conflito marca/domínio com spaCy pt_core_news_sm (fallback regex)
  - BeautifulSoup: extrai texto de HTML antes de passar ao ML e heurísticas
  - unblock_email: corrigido para remover label sem erro 500
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ─── Importações opcionais com fallback gracioso ──────────────────

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False
    logger.warning("yara-python não instalado — camada YARA desactivada")

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False
    logger.warning("beautifulsoup4 não instalado — extracção HTML desactivada")

try:
    import spacy
    try:
        _nlp = spacy.load("pt_core_news_sm")
        _HAS_SPACY = True
    except OSError:
        try:
            _nlp = spacy.load("en_core_web_sm")
            _HAS_SPACY = True
        except OSError:
            _HAS_SPACY = False
            _nlp = None
            logger.warning("Modelos spaCy não encontrados — NER desactivado")
except ImportError:
    _HAS_SPACY = False
    _nlp = None
    logger.warning("spaCy não instalado — NER desactivado")


# ─── YARA Rules (compiladas em memória) ───────────────────────────
# Regras que cobrem padrões de phishing universais e Angola-específicos.
# Não requerem ficheiro externo.

_YARA_SOURCE = r"""
rule PhishingPortuguese {
    meta:
        description = "Padrões de phishing em Português/Angola"
        severity = "high"
    strings:
        $cred1  = "introduza o seu pin" nocase ascii wide
        $cred2  = "confirme os seus dados" nocase ascii wide
        $cred3  = "verificar a sua conta" nocase ascii wide
        $cred4  = "validar a sua conta" nocase ascii wide
        $cred5  = "conta bloqueada" nocase ascii wide
        $cred6  = "acesso suspenso" nocase ascii wide
        $cred7  = "senha expirada" nocase ascii wide
        $cred8  = "palavra-passe expirada" nocase ascii wide
        $cred9  = "dados bancarios" nocase ascii wide
        $cred10 = "codigo de acesso" nocase ascii wide
        $cred11 = "suspensao de conta" nocase ascii wide
        $cred12 = "suspensão de conta" nocase ascii wide
        $cred13 = "atividade suspeita" nocase ascii wide
        $cred14 = "login nao autorizado" nocase ascii wide
        $cred15 = "reativacao de conta" nocase ascii wide
        $urgent1 = "clique aqui" nocase ascii wide
        $urgent2 = "aceda ja" nocase ascii wide
        $urgent3 = "acesse agora" nocase ascii wide
        $urgent4 = "ultimo aviso" nocase ascii wide
        $urgent5 = "24 horas" nocase ascii wide
    condition:
        2 of ($cred*) or
        (1 of ($cred*) and 1 of ($urgent*))
}

rule PhishingAngola {
    meta:
        description = "Phishing com contexto angolano"
        severity = "high"
    strings:
        $brand1  = "multicaixa" nocase ascii wide
        $brand2  = "bai directo" nocase ascii wide
        $brand3  = "bai net" nocase ascii wide
        $brand4  = "bfa net" nocase ascii wide
        $brand5  = "emis" nocase ascii wide
        $action1 = "verificar conta" nocase ascii wide
        $action2 = "confirmar dados" nocase ascii wide
        $action3 = "conta suspensa" nocase ascii wide
        $action4 = "bloqueio imediato" nocase ascii wide
        $action5 = "atualizar dados" nocase ascii wide
        $action6 = "actualizar dados" nocase ascii wide
        $pin1    = " pin " nocase ascii wide
        $pin2    = "codigo pin" nocase ascii wide
        $pin3    = "seu pin" nocase ascii wide
    condition:
        (1 of ($brand*) and 1 of ($action*)) or
        (1 of ($brand*) and 1 of ($pin*))
}

rule PhishingURLPatterns {
    meta:
        description = "URLs com padrões de phishing"
        severity = "medium"
    strings:
        $url1 = /https?:\/\/[^\s]*\.(xyz|top|click|tk|ml|ga|cf|gq|pw|cam|icu)[^\s]*/
        $url2 = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $url3 = /https?:\/\/[^\s]*@[^\s]*/
        $url4 = /https?:\/\/[^\s]*-secure-[^\s]*/
        $url5 = /https?:\/\/[^\s]*-login-[^\s]*/
        $url6 = /https?:\/\/[^\s]*-account-[^\s]*/
        $url7 = /https?:\/\/[^\s]*-verify-[^\s]*/
        $url8 = /https?:\/\/[^\s]*-update-[^\s]*/
        $url9 = /https?:\/\/[^\s]*-banking-[^\s]*/
    condition:
        any of them
}

rule CredentialHarvesting {
    meta:
        description = "Pedido de credenciais + link"
        severity = "critical"
    strings:
        $cred1 = /\bpin\b/i
        $cred2 = /\bsenha\b/i
        $cred3 = /\bpassword\b/i
        $cred4 = /\bcvv\b/i
        $cred5 = /\biban\b/i
        $cred6 = "numero de conta" nocase
        $cred7 = "numero do cartao" nocase
        $link  = /https?:\/\//
        $urgent = /(urgente|imediato|24 horas|bloqueado|suspens)/i
    condition:
        $link and $urgent and 1 of ($cred*)
}
"""

_yara_rules = None
if _HAS_YARA:
    try:
        _yara_rules = yara.compile(source=_YARA_SOURCE)
        logger.info("YARA: %d regras compiladas com sucesso", 4)
    except Exception as e:
        logger.warning("YARA: falha ao compilar regras: %s", e)
        _HAS_YARA = False


# ─── Marcas conhecidas para NER ───────────────────────────────────

_BRAND_NER_MAP: dict[str, list[str]] = {
    "BAI":              ["bai.ao", "baionline.ao"],
    "BFA":              ["bfa.ao", "bfaonline.ao"],
    "BIC":              ["bic.ao", "bicnet.ao"],
    "BPC":              ["bpc.ao"],
    "Atlântico":        ["atlantico.ao"],
    "Standard Bank":    ["standardbank.ao"],
    "Unitel":           ["unitel.ao"],
    "Movicel":          ["movicel.ao"],
    "Africell":         ["africell.ao"],
    "Multicaixa":       ["multicaixa.ao", "emis.ao"],
    "EMIS":             ["emis.ao"],
    "Sonangol":         ["sonangol.ao"],
    "TAAG":             ["taag.ao"],
    "Google":           ["google.com", "accounts.google.com", "notifications.google.com"],
    "Microsoft":        ["microsoft.com", "office.com", "outlook.com"],
    "PayPal":           ["paypal.com", "paypal.me"],
    "Apple":            ["apple.com", "icloud.com"],
    "Amazon":           ["amazon.com", "aws.amazon.com"],
    "Netflix":          ["netflix.com"],
    "DHL":              ["dhl.com", "dhl.de"],
    "FedEx":            ["fedex.com"],
    "LinkedIn":         ["linkedin.com"],
    "Facebook":         ["facebook.com", "facebookmail.com"],
    "Twilio":           ["twilio.com", "team.twilio.com", "sendgrid.net"],
    "SendGrid":         ["sendgrid.net", "sendgrid.com"],
    "Stripe":           ["stripe.com"],
    "GitHub":           ["github.com", "mg.github.com"],
}

# Lookup inverso: domínio → brand
_DOMAIN_TO_BRAND: dict[str, str] = {}
for _brand, _domains in _BRAND_NER_MAP.items():
    for _d in _domains:
        _DOMAIN_TO_BRAND[_d.lower()] = _brand

# Regex de fallback para NER sem spaCy
_BRAND_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(b) for b in _BRAND_NER_MAP.keys()) + r")\b",
    re.IGNORECASE,
)


# ─── ESPs e serviços legítimos ────────────────────────────────────

_LEGIT_ESPS: set[str] = {
    "sendgrid.net", "mailchimp.com", "amazonses.com", "mandrillapp.com",
    "sparkpostmail.com", "mailgun.org", "exacttarget.com", "salesforce.com",
    "mailjet.com", "sendinblue.com", "brevo.com", "constantcontact.com",
    "campaignmonitor.com", "klaviyo.com", "hubspot.com", "zendesk.com",
    "freshdesk.com", "intercom.io", "twilio.com", "google.com",
    "facebookmail.com", "instagrammail.com", "stripe.com", "github.com",
    "netlify.com", "vercel.com", "team.twilio.com",
}

_KNOWN_SERVICES: set[str] = _LEGIT_ESPS | {
    "google.com", "accounts.google.com", "notifications.google.com",
    "no-reply.accounts.google.com", "bai.ao", "bfa.ao", "bic.ao", "bpc.ao",
    "unitel.ao", "movicel.ao", "africell.ao", "multicaixa.ao", "emis.ao",
    "sonangol.ao", "taag.ao", "governo.ao", "bna.ao",
}

_FREE_EMAIL: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "mail.com", "protonmail.com", "icloud.com", "yandex.com",
}

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


# ─── Resultado estruturado ────────────────────────────────────────

@dataclass
class HybridResult:
    score: int = 0
    verdict: str = "SEGURO"
    reasons: list[str] = field(default_factory=list)
    layers: dict[str, Any] = field(default_factory=dict)
    # Campos exportados para compatibilidade com orchestrator
    ml: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    brand_detected: str | None = None
    is_typosquat: bool = False
    is_spoofed: bool = False
    spf_pass: bool = True
    dkim_pass: bool = True
    dmarc_pass: bool = True
    yara_matched: list[str] = field(default_factory=list)
    ner_brands: list[str] = field(default_factory=list)
    sender: str = ""
    domain: str = ""
    urls_checked: list[dict] = field(default_factory=list)


# ─── CAMADA 1: HTML → Texto limpo ────────────────────────────────

def extract_text_from_html(raw: str) -> str:
    """Extrai texto limpo de HTML com BeautifulSoup. Fallback para regex."""
    if not raw:
        return ""
    if not _HAS_BS4:
        # Fallback: remover tags HTML com regex
        clean = re.sub(r"<[^>]+>", " ", raw)
        clean = re.sub(r"&[a-z]+;", " ", clean)
        return re.sub(r"\s+", " ", clean).strip()
    try:
        soup = BeautifulSoup(raw, "lxml")
        # Remover script/style
        for tag in soup(["script", "style", "meta", "link"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        return re.sub(r"\s+", " ", text).strip()
    except Exception:
        try:
            soup = BeautifulSoup(raw, "html.parser")
            return soup.get_text(separator=" ", strip=True)
        except Exception:
            return raw


# ─── CAMADA 2: YARA ───────────────────────────────────────────────

def run_yara(text: str) -> tuple[int, list[str]]:
    """
    Aplica regras YARA ao texto.
    Retorna (score_adicional, regras_matched).
    """
    if not _HAS_YARA or not _yara_rules or not text:
        return 0, []

    score = 0
    matched_rules: list[str] = []

    try:
        text_bytes = text.encode("utf-8", errors="replace")[:65535]
        matches = _yara_rules.match(data=text_bytes)

        severity_scores = {
            "critical": 45,
            "high":     30,
            "medium":   20,
        }

        for match in matches:
            rule_name = match.rule
            severity = match.meta.get("severity", "medium")
            points = severity_scores.get(severity, 20)
            score += points
            matched_rules.append(rule_name)
            logger.debug("YARA match: %s (severity=%s, +%d pts)", rule_name, severity, points)

    except Exception as e:
        logger.warning("YARA scan falhou: %s", e)

    return min(score, 80), matched_rules


# ─── CAMADA 3: NER (spaCy + fallback regex) ───────────────────────

def run_ner(text: str, sender_domain: str) -> tuple[int, list[str], list[str]]:
    """
    Named Entity Recognition para detectar conflito marca ↔ domínio.

    Cenário de phishing clássico:
      - Email menciona "BAI" ou "Multicaixa" no corpo
      - Mas é enviado de um domínio completamente diferente

    Retorna (score_ner, marcas_detectadas, razoes).
    """
    if not text or not sender_domain:
        return 0, [], []

    brands_in_text: list[str] = []

    # spaCy NER
    if _HAS_SPACY and _nlp is not None:
        try:
            doc = _nlp(text[:5000])  # limitar para performance
            for ent in doc.ents:
                if ent.label_ in ("ORG", "PRODUCT", "BRAND"):
                    name = ent.text.strip()
                    # Verificar se é uma das nossas marcas conhecidas
                    for brand in _BRAND_NER_MAP:
                        if brand.lower() in name.lower():
                            if brand not in brands_in_text:
                                brands_in_text.append(brand)
        except Exception as e:
            logger.debug("spaCy NER falhou: %s — usando regex", e)

    # Fallback ou complemento: regex de marcas
    for m in _BRAND_REGEX.finditer(text[:5000]):
        brand = m.group(0)
        # Normalizar capitalização
        for known_brand in _BRAND_NER_MAP:
            if known_brand.lower() == brand.lower():
                if known_brand not in brands_in_text:
                    brands_in_text.append(known_brand)

    if not brands_in_text:
        return 0, [], []

    # Verificar conflito: a marca está no texto mas o remetente não é o domínio oficial?
    score = 0
    reasons = []

    sender_is_legit_for_brand = False
    for brand in brands_in_text:
        official_domains = _BRAND_NER_MAP.get(brand, [])
        for od in official_domains:
            if od.lower() == sender_domain.lower() or sender_domain.endswith("." + od.lower()):
                sender_is_legit_for_brand = True
                break
            # ESP que é legítimo para essa marca
            if any(esp in sender_domain for esp in _LEGIT_ESPS):
                sender_is_legit_for_brand = True
                break
        if sender_is_legit_for_brand:
            break

    if not sender_is_legit_for_brand and brands_in_text:
        score += 25 * min(len(brands_in_text), 2)
        brand_list = ", ".join(brands_in_text[:3])
        reasons.append(
            f"NER: email menciona marca(s) '{brand_list}' "
            f"mas remetente é '{sender_domain}' (domínio não oficial)"
        )

    return min(score, 50), brands_in_text, reasons


# ─── CAMADA 4: Análise estrutural de URL ──────────────────────────

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".cam", ".icu", ".surf", ".monster", ".live", ".online",
    ".site", ".website", ".press", ".space", ".fun", ".host",
    ".shop", ".store", ".vip", ".win", ".bid", ".stream",
}

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd",
    "ow.ly", "cutt.ly", "rebrand.ly", "rb.gy", "short.link",
}

_SUSPICIOUS_HOSTING = {
    "ngrok.io", "ngrok-free.app", "netlify.app", "github.io",
    "vercel.app", "pages.dev", "glitch.me", "replit.co",
    "000webhost.com", "weebly.com", "wixsite.com",
    "firebaseapp.com", "web.app",
}


def analyze_url_local(url: str) -> tuple[int, list[str]]:
    """Análise estrutural de URL sem chamadas de rede."""
    score = 0
    reasons: list[str] = []

    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower().lstrip("www.")
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
    except Exception:
        return 0, []

    if not domain:
        return 0, []

    # IP como hostname → phishing quase certo
    try:
        ipaddress.ip_address(domain)
        score += 40
        reasons.append(f"URL usa endereço IP directamente: {domain}")
        return min(100, score), reasons
    except ValueError:
        pass

    # TLD suspeito
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"TLD suspeito: {tld}")
            break

    # Hosting suspeito
    for host in _SUSPICIOUS_HOSTING:
        if host in domain:
            score += 30
            reasons.append(f"Domínio em serviço de hosting suspeito: {host}")
            break

    # Encurtador
    if domain in _SHORTENERS:
        score += 20
        reasons.append(f"Encurtador de URL: {domain}")

    # @ na URL antes do ? (credential harvesting)
    url_path_part = url.split("?")[0]
    if "@" in url_path_part:
        score += 40
        reasons.append("URL contém '@' no caminho (possível credential harvesting)")

    # Muitos hifens no domínio
    base = domain.split(".")[0]
    if base.count("-") >= 3:
        score += 20
        reasons.append(f"Domínio com múltiplos hífens: {domain}")

    # Domínio muito longo
    if len(domain) > 40:
        score += 15
        reasons.append(f"Domínio anormalmente longo ({len(domain)} chars)")

    # Palavras de phishing no path/query
    phishing_path_words = [
        "login", "signin", "account", "verify", "confirm",
        "secure", "update", "banking", "password", "credential",
        "validate", "suspend", "recover", "unlock", "wallet",
    ]
    path_full = path + " " + query
    found_words = [w for w in phishing_path_words if w in path_full]
    if len(found_words) >= 2:
        score += 20
        reasons.append(f"Palavras de phishing no URL: {', '.join(found_words[:3])}")
    elif found_words:
        score += 8

    # HTTPS não presente (em 2026, sites legítimos usam HTTPS)
    if url.startswith("http://"):
        score += 10
        reasons.append("URL usa HTTP (não seguro)")

    return min(100, score), reasons


# ─── CAMADA 5: Typosquatting ──────────────────────────────────────

_BRAND_DOMAINS_TYPO: dict[str, str] = {
    "bai.ao": "BAI", "bfa.ao": "BFA", "bic.ao": "BIC", "bpc.ao": "BPC",
    "atlantico.ao": "Banco Atlântico", "standardbank.ao": "Standard Bank",
    "unitel.ao": "Unitel", "movicel.ao": "Movicel", "africell.ao": "Africell",
    "multicaixa.ao": "Multicaixa", "emis.ao": "EMIS",
    "paypal.com": "PayPal", "amazon.com": "Amazon",
    "microsoft.com": "Microsoft", "apple.com": "Apple",
    "netflix.com": "Netflix", "google.com": "Google",
    "dhl.com": "DHL", "facebook.com": "Facebook",
}


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def check_typosquatting(domain: str) -> tuple[bool, str, str]:
    """Detecta typosquatting com Levenshtein."""
    if not domain:
        return False, "", ""
    d = domain.lower().lstrip("www.")
    if d in _BRAND_DOMAINS_TYPO:
        return False, "", ""
    for brand_d, brand_name in _BRAND_DOMAINS_TYPO.items():
        dist = _levenshtein(d, brand_d)
        if 0 < dist <= 2:
            return True, brand_name, brand_d
        brand_base = brand_d.split(".")[0]
        d_base = d.split(".")[0]
        if len(brand_base) >= 4 and brand_base in d_base and d_base != brand_base:
            return True, brand_name, brand_d
    return False, "", ""


# ─── CAMADA 6: Display-name spoofing ─────────────────────────────

def check_display_name_spoofing(sender: str) -> tuple[bool, str]:
    """Detecta quando display name imita uma marca mas o domínio é diferente."""
    if not sender or "@" not in sender or "<" not in sender:
        return False, ""
    try:
        display = sender[: sender.index("<")].strip().strip('"').lower()
        email_part = sender[sender.index("<") + 1 :].strip(">").strip()
        if not display or "@" not in email_part:
            return False, ""
        email_domain = email_part.split("@")[-1].lower()
    except Exception:
        return False, ""

    # ESPs legítimos → nunca spoofing
    if any(esp in email_domain for esp in _LEGIT_ESPS):
        return False, ""

    for brand, official_domains in _BRAND_NER_MAP.items():
        brand_lower = brand.lower()
        brand_words = brand_lower.split()
        if any(word in display for word in brand_words if len(word) >= 4):
            is_official = any(
                email_domain == od.lower() or email_domain.endswith("." + od.lower())
                for od in official_domains
            )
            if not is_official:
                return True, brand
    return False, ""


# ─── Extracção de domínio do remetente ───────────────────────────

def extract_sender_domain(sender: str) -> str:
    if not sender:
        return ""
    # "Name <email@domain.com>" ou "email@domain.com"
    if "<" in sender:
        match = re.search(r"<[^>]*@([^>]+)>", sender)
        if match:
            return match.group(1).strip().lower()
    if "@" in sender:
        return sender.split("@")[-1].strip(">").strip().lower()
    return ""


def is_legit_sender(domain: str) -> bool:
    """True se o domínio do remetente é de um serviço/ESP legítimo conhecido."""
    if not domain:
        return False
    if domain in _KNOWN_SERVICES:
        return True
    for known in _KNOWN_SERVICES:
        if domain.endswith("." + known):
            return True
    if any(esp in domain for esp in _LEGIT_ESPS):
        return True
    return False


# ─── Pipeline HÍBRIDO principal ───────────────────────────────────

async def hybrid_analyze_email(
    sender: str,
    headers: str,
    body: str | None,
    *,
    run_external_apis: bool = True,
    timeout_total: float = 55.0,
) -> HybridResult:
    """
    Análise híbrida completa de email.

    Executa todas as camadas em cascata com fallback gracioso.
    Nunca retorna score 0 apenas por timeout — mantém score parcial.
    """
    t_start = time.monotonic()
    sender = (sender or "").strip()
    body = body or ""
    headers_str = headers or ""
    domain = extract_sender_domain(sender)
    is_legit = is_legit_sender(domain)

    result = HybridResult(sender=sender, domain=domain)

    # ── Extrair texto limpo de HTML ────────────────────────────────
    clean_body = extract_text_from_html(body) if body else ""
    content = clean_body + " " + headers_str
    urls_in_body = URL_RE.findall(body or "")

    # ═════════════════════════════════════════════════════════════
    # CAMADA 1: YARA
    # ═════════════════════════════════════════════════════════════
    try:
        yara_score, yara_matches = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, run_yara, content),
            timeout=3.0,
        )
        result.yara_matched = yara_matches
        result.layers["yara"] = {"score": yara_score, "matches": yara_matches}
        if yara_score > 0:
            if is_legit:
                yara_score = yara_score // 3  # penalidade reduzida para ESPs legítimos
            result.score += yara_score
            if yara_matches:
                result.reasons.append(
                    f"YARA: {len(yara_matches)} regra(s) activada(s): {', '.join(yara_matches)}"
                )
    except Exception as e:
        logger.debug("YARA layer falhou: %s", e)
        result.layers["yara"] = {"error": str(e)}

    # ═════════════════════════════════════════════════════════════
    # CAMADA 2: NER
    # ═════════════════════════════════════════════════════════════
    try:
        ner_score, ner_brands, ner_reasons = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, run_ner, content, domain),
            timeout=5.0,
        )
        result.ner_brands = ner_brands
        result.layers["ner"] = {"score": ner_score, "brands": ner_brands}
        if ner_brands:
            result.brand_detected = ner_brands[0] if ner_brands else None
        if ner_score > 0 and not is_legit:
            result.score += ner_score
            result.reasons.extend(ner_reasons)
    except Exception as e:
        logger.debug("NER layer falhou: %s", e)
        result.layers["ner"] = {"error": str(e)}

    # ═════════════════════════════════════════════════════════════
    # CAMADA 3: Análise local (heurísticas PT + URLs + spoofing)
    # ═════════════════════════════════════════════════════════════
    try:
        from backend.services.orchestrator import quick_local_analysis
        local = quick_local_analysis(sender, headers_str, body or "")
        local_score = local.get("score", 0)
        local_reasons = local.get("reasons", [])
        result.layers["heuristics"] = {"score": local_score}

        if local_score > 0:
            if is_legit and local_score < 50:
                local_score = local_score // 3
            result.score += local_score
            result.reasons.extend(local_reasons)

        result.is_typosquat = local.get("is_typosquat", False)
        result.is_spoofed = local.get("is_spoofed", False)

    except Exception as e:
        logger.warning("Heuristics layer falhou: %s", e)
        result.layers["heuristics"] = {"error": str(e)}

    # URLs locais
    max_url_score = 0
    for url in urls_in_body[:5]:
        u_score, u_reasons = analyze_url_local(url)
        if u_score > max_url_score:
            max_url_score = u_score
        if u_score >= 30:
            result.reasons.extend(u_reasons)
    if max_url_score > 0 and not is_legit:
        result.score += max_url_score // 2

    # Typosquatting no domínio do remetente
    if not is_legit:
        is_typo, typo_brand, typo_domain = check_typosquatting(domain)
        if is_typo:
            result.is_typosquat = True
            result.score += 40
            result.reasons.append(
                f"Typosquatting: domínio '{domain}' imita '{typo_brand}' ({typo_domain})"
            )

    # Display-name spoofing
    is_spoofed, spoofed_brand = check_display_name_spoofing(sender)
    if is_spoofed:
        result.is_spoofed = True
        result.score += 35
        result.reasons.append(
            f"Display-name spoofing: aparenta ser '{spoofed_brand}' mas enviado de '{domain}'"
        )

    # ═════════════════════════════════════════════════════════════
    # CAMADA 4: ML (Groq)
    # ═════════════════════════════════════════════════════════════
    ml: dict = {}
    elapsed = time.monotonic() - t_start
    ml_timeout = max(5.0, min(12.0, timeout_total - elapsed - 15.0))

    try:
        from backend.services.ml_classifier import classify_with_groq
        ml = dict(await asyncio.wait_for(
            classify_with_groq(clean_body or headers_str, "email"),
            timeout=ml_timeout,
        ))
        result.ml = ml
        ml_score = int(ml.get("ml_score", 0))
        ml_confidence = float(ml.get("confidence", 0))
        ml_reasoning = str(ml.get("reasoning", ""))
        result.layers["ml"] = {"score": ml_score, "confidence": ml_confidence}

        if ml_reasoning:
            result.reasons.insert(0, f"IA: {ml_reasoning}")

        # ML override: remetente legítimo + ML seguro → cap score
        if is_legit and ml_score < 30 and ml_confidence >= 0.5 and result.score < 50:
            result.score = min(result.score, 20)
            result.layers["ml"]["override"] = "legit_sender_ml_safe"
        elif ml_score >= 70:
            result.score = max(result.score, ml_score - 5)
        elif ml_score >= 50:
            result.score = max(result.score, ml_score)

    except asyncio.TimeoutError:
        logger.info("ML timeout para domínio %s — continuando sem ML", domain)
        result.layers["ml"] = {"error": "timeout", "fallback": "heuristics_only"}
        # Timeout do ML NÃO reduz score — mantém score das camadas anteriores
    except Exception as e:
        logger.warning("ML falhou: %s", e)
        result.layers["ml"] = {"error": str(e)}

    # ═════════════════════════════════════════════════════════════
    # CAMADA 5: DNS + SPF/DKIM/DMARC
    # ═════════════════════════════════════════════════════════════
    if not is_legit and domain:
        elapsed = time.monotonic() - t_start
        dns_timeout = max(3.0, min(5.0, timeout_total - elapsed - 12.0))
        try:
            from backend.services.dns_check import check_spf_dkim
            dns_r = dict(await asyncio.wait_for(check_spf_dkim(domain), timeout=dns_timeout))
            result.dns = dns_r
            result.spf_pass = dns_r.get("spf") == "pass"
            result.dkim_pass = dns_r.get("dkim") == "pass"
            result.dmarc_pass = dns_r.get("dmarc") == "pass"
            result.layers["dns"] = dns_r

            if not result.spf_pass:
                result.score += 15
                result.reasons.append(f"SPF falhou para o domínio '{domain}'")
            if not result.dkim_pass:
                result.score += 12
                result.reasons.append(f"DKIM não verificado para '{domain}'")
            if not result.dmarc_pass:
                result.score += 8
                result.reasons.append(f"DMARC ausente/falhou para '{domain}'")

        except asyncio.TimeoutError:
            logger.info("DNS timeout para %s", domain)
            result.layers["dns"] = {"error": "timeout"}
        except Exception as e:
            logger.debug("DNS check falhou: %s", e)
            result.layers["dns"] = {"error": str(e)}

    # ═════════════════════════════════════════════════════════════
    # CAMADA 6: APIs Externas (VT + GSB + URLScan + AbuseIPDB + DNSBL)
    # ═════════════════════════════════════════════════════════════
    elapsed = time.monotonic() - t_start
    remaining = timeout_total - elapsed
    # CORRIGIDO v12: removido threshold "score > 15" que bloqueava APIs
    # quando URL não tinha sinais locais (ex: URLs em PhishTank/OpenPhish
    # que são novas e ainda não têm padrões conhecidos).
    # APIs externas correm SEMPRE que há URLs ou domínio para verificar,
    # independentemente do score local.
    should_run_apis = (
        run_external_apis
        and not is_legit
        and remaining > 8.0
        and (urls_in_body or domain)
    )

    if should_run_apis:
        api_results = await _run_external_apis(
            urls=urls_in_body[:3],
            domain=domain,
            timeout=min(remaining - 3.0, 12.0),
        )
        result.layers["external_apis"] = api_results
        result.urls_checked = api_results.get("url_details", [])

        ext_score = api_results.get("score", 0)
        ext_reasons = api_results.get("reasons", [])
        apis_positive = api_results.get("apis_positive", 0)

        if ext_score > 0:
            result.score = max(result.score, result.score + ext_score // 2)
            result.reasons.extend(ext_reasons)

        # Consenso forte: ≥2 APIs confirmam ameaça → score mínimo 80
        if apis_positive >= 2:
            result.score = max(result.score, 80)

    # ─── Score final ──────────────────────────────────────────────
    # Anti-FP para ESPs/serviços legítimos
    if is_legit and result.score < 50 and not result.is_typosquat and not result.is_spoofed:
        result.score = min(result.score, 25)

    result.score = max(0, min(100, result.score))

    # Deduplicate reasons
    result.reasons = list(dict.fromkeys(result.reasons))

    if result.score >= 60:
        result.verdict = "NÃO SEGURO"
    elif result.score >= 30:
        result.verdict = "SUSPEITO"
    else:
        result.verdict = "SEGURO"

    elapsed_total = time.monotonic() - t_start
    logger.info(
        "Análise híbrida concluída: score=%d, verdict=%s, layers=%s, tempo=%.1fs",
        result.score, result.verdict,
        list(result.layers.keys()),
        elapsed_total,
    )

    return result


# ─── APIs Externas em paralelo ────────────────────────────────────

async def _run_external_apis(
    urls: list[str],
    domain: str,
    timeout: float = 10.0,
) -> dict:
    """
    Executa todas as APIs externas em paralelo com timeout global.

    APIs:
      - VirusTotal (por URL)
      - Google Safe Browsing (por URL)
      - URLScan.io (verificar existente, sem novo scan)
      - AbuseIPDB (por IP do domínio)
      - DNSBL (por domínio)

    Retorna score de consenso + detalhes por API.
    """
    from backend.services.external_apis import (
        check_virustotal,
        check_safe_browsing,
        check_urlscan_existing,
        check_abuseipdb,
        phishing_blacklist_check,   # PhishTank + OpenPhish + URLhaus — ADICIONADO v12
    )

    score = 0
    reasons: list[str] = []
    url_details: list[dict] = []
    apis_positive = 0

    # ── Resolver IP do domínio para AbuseIPDB ─────────────────────
    target_ip: str | None = None
    if domain:
        try:
            target_ip = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, domain),
                timeout=3.0,
            )
        except Exception:
            pass

    # ── Preparar tasks ────────────────────────────────────────────
    tasks = {}

    if urls:
        primary_url = urls[0]
        tasks["vt"]        = check_virustotal(primary_url)
        tasks["gsb"]       = check_safe_browsing(primary_url)
        tasks["urlscan"]   = check_urlscan_existing(primary_url)
        # ADICIONADO v12: blacklists em paralelo (PhishTank + OpenPhish + URLhaus)
        # Detecta URLs confirmadas por múltiplas fontes da comunidade.
        tasks["blacklist"] = phishing_blacklist_check(primary_url)

    if target_ip:
        tasks["abuseipdb"] = check_abuseipdb(target_ip)

    if domain:
        tasks["dnsbl"] = _check_dnsbl_async(domain)

    if not tasks:
        return {"score": 0, "reasons": [], "apis_positive": 0, "url_details": []}

    # ── Executar em paralelo ──────────────────────────────────────
    task_names = list(tasks.keys())
    task_coros = list(tasks.values())

    try:
        raw_results = await asyncio.wait_for(
            asyncio.gather(*task_coros, return_exceptions=True),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("APIs externas: timeout global de %.1fs", timeout)
        return {"score": score, "reasons": reasons, "apis_positive": apis_positive, "url_details": []}

    api_results = dict(zip(task_names, raw_results))

    # ── Processar VirusTotal ─────────────────────────────────────
    vt = api_results.get("vt", {})
    if isinstance(vt, dict) and not isinstance(vt, Exception):
        vt_mal = int(vt.get("malicious", 0))
        vt_sus = int(vt.get("suspicious", 0))
        if vt_mal >= 10:
            score = max(score, 90)
            reasons.append(f"VirusTotal: {vt_mal} motores detectaram ameaça CRÍTICA")
            apis_positive += 1
        elif vt_mal >= 5:
            score = max(score, 80)
            reasons.append(f"VirusTotal: {vt_mal} motores maliciosos (ALTO)")
            apis_positive += 1
        elif vt_mal >= 3:
            score = max(score, 65)
            reasons.append(f"VirusTotal: {vt_mal} motores maliciosos")
            apis_positive += 1
        elif vt_mal >= 2:
            score = max(score, 50)
            reasons.append(f"VirusTotal: {vt_mal} motores maliciosos")
        elif vt_mal == 1:
            score = max(score, 25)
            reasons.append("VirusTotal: 1 motor malicioso (inconclusivo)")
        elif vt_sus >= 3:
            score = max(score, 35)
            reasons.append(f"VirusTotal: {vt_sus} motores suspeitos")

    # ── Processar Google Safe Browsing ────────────────────────────
    gsb = api_results.get("gsb", {})
    if isinstance(gsb, dict) and not isinstance(gsb, Exception):
        if gsb.get("threat"):
            gsb_types = gsb.get("types", [])
            score = max(score, 85)
            type_str = ", ".join(t for t in gsb_types if t) or "tipo desconhecido"
            reasons.append(f"Google Safe Browsing: AMEAÇA detectada ({type_str})")
            apis_positive += 1

    # ── Processar URLScan ─────────────────────────────────────────
    urlscan = api_results.get("urlscan", {})
    if isinstance(urlscan, dict) and not isinstance(urlscan, Exception):
        if urlscan.get("malicious"):
            score = max(score, 60)
            reasons.append("URLScan.io: URL marcada como maliciosa")
            apis_positive += 1
        elif urlscan.get("score", 0) >= 70:
            score = max(score, 50)
            reasons.append(f"URLScan.io: score de risco {urlscan['score']}")

    # ── Processar AbuseIPDB ───────────────────────────────────────
    abuse = api_results.get("abuseipdb", {})
    if isinstance(abuse, dict) and not isinstance(abuse, Exception):
        abuse_score = int(abuse.get("abuse_score", 0))
        if abuse_score >= 80:
            score = max(score, 70)
            reasons.append(
                f"AbuseIPDB: IP {target_ip} com score de abuso {abuse_score}/100"
            )
            apis_positive += 1
        elif abuse_score >= 50:
            score = max(score, 45)
            reasons.append(f"AbuseIPDB: IP suspeito (score={abuse_score})")

    # ── Processar DNSBL ───────────────────────────────────────────
    dnsbl = api_results.get("dnsbl", {})
    if isinstance(dnsbl, dict) and not isinstance(dnsbl, Exception):
        dnsbl_hits = dnsbl.get("hits", [])
        if dnsbl_hits:
            score = max(score, 55)
            reasons.append(f"DNSBL: domínio listado em {', '.join(dnsbl_hits[:2])}")
            apis_positive += 1

    # ── Processar Blacklists (PhishTank + OpenPhish + URLhaus) ────
    # ADICIONADO v12: fonte comunitária de phishing confirmado.
    # Uma confirmação de blacklist → score mínimo 90 (phishing activo).
    bl = api_results.get("blacklist", {})
    if isinstance(bl, dict) and not isinstance(bl, Exception):
        if bl.get("blacklisted"):
            bl_reasons = bl.get("reasons", [])
            bl_score   = bl.get("score", 90)
            score      = max(score, bl_score)
            reasons.extend(bl_reasons)
            apis_positive += 2   # blacklist confirmada = 2 sinais (PhishTank/OpenPhish são verificados por humanos)
            logger.info("BLACKLIST HIT: score=%d, motivos=%s", bl_score, bl_reasons[:2])
        elif bl.get("score", 0) > 0:
            # Na base de dados mas não confirmado
            score = max(score, bl.get("score", 0))
            reasons.extend(bl.get("reasons", []))

    # ── Consenso ≥2 APIs → confirmar ─────────────────────────────
    if apis_positive >= 2:
        score = max(score, 80)
        reasons.append(f"CONSENSO: {apis_positive} APIs independentes confirmam ameaça")

    # ── URL details para o frontend ──────────────────────────────
    if urls:
        url_details.append({
            "url":       urls[0],
            "vt":        vt if isinstance(vt, dict) else {},
            "gsb":       gsb if isinstance(gsb, dict) else {},
            "urlscan":   urlscan if isinstance(urlscan, dict) else {},
            "blacklist": bl if isinstance(bl, dict) else {},
            "score":     score,
        })

    return {
        "score":         min(100, score),
        "reasons":       reasons,
        "apis_positive": apis_positive,
        "url_details":   url_details,
        "abuseipdb":     abuse if isinstance(abuse, dict) else {},
        "dnsbl":         dnsbl if isinstance(dnsbl, dict) else {},
    }


# ─── DNSBL assíncrono ────────────────────────────────────────────

_DNSBL_ZONES = [
    "multi.surbl.org",
    "dbl.spamhaus.org",
    "uribl.com",
]


def _dnsbl_sync(domain: str) -> dict:
    hits: list[str] = []
    for zone in _DNSBL_ZONES:
        query = f"{domain}.{zone}"
        try:
            socket.getaddrinfo(query, None, timeout=2)
            hits.append(zone)
        except (socket.gaierror, OSError):
            pass
    return {"flagged": bool(hits), "hits": hits}


async def _check_dnsbl_async(domain: str) -> dict:
    try:
        return await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _dnsbl_sync, domain),
            timeout=4.0,
        )
    except asyncio.TimeoutError:
        return {"flagged": False, "hits": [], "error": "timeout"}
    except Exception as e:
        return {"flagged": False, "hits": [], "error": str(e)}
    