"""
backend/services/hybrid_analyzer.py
─────────────────────────────────────────────────────────────────────────────
MOTOR DE ANÁLISE HÍBRIDA v17 — PhishGuard

CORRECÇÕES v17:
- Extração de URLs melhorada (assunto + corpo) com regex e fallback.
- APIs externas (VirusTotal, Google Safe Browsing, PhishTank, URLScan)
  agora são chamadas sempre que um URL é encontrado, mesmo que seja no assunto.
- Sem timeout global – cada API tem o seu próprio timeout.
- Logs detalhados para diagnóstico.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ─── Importações opcionais com fallback gracioso ──────────────────
try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False
    logger.warning("yara-python não instalado – camada YARA desactivada")

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False
    logger.warning("beautifulsoup4 não instalado – extracção HTML desactivada")

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
            logger.warning("Modelos spaCy não encontrados – NER desactivado")
except ImportError:
    _HAS_SPACY = False
    _nlp = None
    logger.warning("spaCy não instalado – NER desactivado")


# ─── YARA Rules (compiladas em memória) ───────────────────────────

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
        2 of ($cred*) or (1 of ($cred*) and 1 of ($urgent*))
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
        (1 of ($brand*) and 1 of ($action*)) or (1 of ($brand*) and 1 of ($pin*))
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
    condition: any of them
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
    condition: $link and $urgent and 1 of ($cred*)
}
"""

_yara_rules = None
if _HAS_YARA:
    try:
        _yara_rules = yara.compile(source=_YARA_SOURCE)
        logger.info("YARA: regras compiladas com sucesso")
    except Exception as e:
        logger.warning("YARA: falha ao compilar regras: %s", e)
        _HAS_YARA = False

# ─── Marcas conhecidas para NER ───────────────────────────────────

_BRAND_NER_MAP: dict[str, list[str]] = {
    "BAI": ["bai.ao", "baionline.ao"],
    "BFA": ["bfa.ao", "bfaonline.ao"],
    "BIC": ["bic.ao", "bicnet.ao"],
    "BPC": ["bpc.ao"],
    "Atlântico": ["atlantico.ao"],
    "Standard Bank": ["standardbank.ao"],
    "Unitel": ["unitel.ao"],
    "Movicel": ["movicel.ao"],
    "Africell": ["africell.ao"],
    "Multicaixa": ["multicaixa.ao", "emis.ao"],
    "EMIS": ["emis.ao"],
    "Sonangol": ["sonangol.ao"],
    "TAAG": ["taag.ao"],
    "Google": ["google.com", "accounts.google.com", "notifications.google.com"],
    "Microsoft": ["microsoft.com", "office.com", "outlook.com"],
    "PayPal": ["paypal.com", "paypal.me"],
    "Apple": ["apple.com", "icloud.com"],
    "Amazon": ["amazon.com", "aws.amazon.com"],
    "Netflix": ["netflix.com"],
    "DHL": ["dhl.com", "dhl.de"],
    "FedEx": ["fedex.com"],
    "LinkedIn": ["linkedin.com"],
    "Facebook": ["facebook.com", "facebookmail.com"],
    "Twilio": ["twilio.com", "team.twilio.com", "sendgrid.net"],
    "SendGrid": ["sendgrid.net", "sendgrid.com"],
    "Stripe": ["stripe.com"],
    "GitHub": ["github.com", "mg.github.com"],
}

_DOMAIN_TO_BRAND: dict[str, str] = {}
for _brand, _domains in _BRAND_NER_MAP.items():
    for _d in _domains:
        _DOMAIN_TO_BRAND[_d.lower()] = _brand

_BRAND_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(b) for b in _BRAND_NER_MAP.keys()) + r")\b",
    re.IGNORECASE,
)

_LEGIT_ESPS = {
    "sendgrid.net", "mailchimp.com", "amazonses.com", "mandrillapp.com",
    "sparkpostmail.com", "mailgun.org", "exacttarget.com", "salesforce.com",
    "mailjet.com", "sendinblue.com", "brevo.com", "constantcontact.com",
    "campaignmonitor.com", "klaviyo.com", "hubspot.com", "zendesk.com",
    "freshdesk.com", "intercom.io", "twilio.com", "google.com",
    "facebookmail.com", "instagrammail.com", "stripe.com", "github.com",
    "netlify.com", "vercel.com", "team.twilio.com",
}

_KNOWN_SERVICES = _LEGIT_ESPS | {
    "google.com", "accounts.google.com", "notifications.google.com",
    "no-reply.accounts.google.com", "bai.ao", "bfa.ao", "bic.ao", "bpc.ao",
    "unitel.ao", "movicel.ao", "africell.ao", "multicaixa.ao", "emis.ao",
    "sonangol.ao", "taag.ao", "governo.ao", "bna.ao",
}

# ─── Expressões regulares para URLs ───────────────────────────────

# Padrão mais abrangente para capturar URLs (inclui caracteres especiais)
URL_RE = re.compile(r"https?://[^\s<>\"')\\]]+", re.IGNORECASE)
# Fallback: qualquer string que comece com http:// ou https:// e termine com espaço ou fim de linha
URL_RE_FALLBACK = re.compile(r"https?://\S+")

_PHISHING_KEYWORDS = [
    r"\bpin\b", r"\bsenha\b", r"\bpassword\b", r"\bcvv\b", r"\biban\b",
    "codigo de acesso", "numero de conta", "numero do cartao",
    "dados bancarios", "dados bancários",
    r"urgent[ei]?", "urgente", "imediato", "último aviso", "ultimo aviso",
    "24 horas", "48 horas", "conta bloqueada", "acesso suspenso",
    "suspensão de conta", "suspensao de conta", "senha expirada",
    "palavra-passe expirada", "atividade suspeita", "login não autorizado",
    "login nao autorizado", "reativação de conta", "reativacao de conta",
    "clique aqui", "aceda já", "aceda ja", "acesse agora",
    "verificar a sua conta", "confirme os seus dados", "valide a sua conta",
    "multicaixa", "bai directo", "bai net", "bfa net",
    "conta suspensa", "bloqueio imediato",
]
_PHISHING_KW_RE = re.compile("|".join(_PHISHING_KEYWORDS), re.IGNORECASE)
_ALERT_EMOJI_RE = re.compile(r"[🚨⚠️🔴🔒❗❕‼️🛑🚫]")


@dataclass
class HybridResult:
    score: int = 0
    verdict: str = "SEGURO"
    reasons: list[str] = field(default_factory=list)
    layers: dict[str, Any] = field(default_factory=dict)
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
    subject: str = ""
    urls_checked: list[dict] = field(default_factory=list)


# ─── Funções auxiliares ───────────────────────────────────────────

def analyze_keywords(subject: str, body: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    if subject:
        matches = _PHISHING_KW_RE.findall(subject)
        if matches:
            unique = list(dict.fromkeys(m.lower() for m in matches))
            score += min(35, len(unique) * 12)
            reasons.append(f"Palavras-chave suspeitas no assunto: {', '.join(unique[:5])}")
        if _ALERT_EMOJI_RE.findall(subject):
            score += 10
            reasons.append("Emojis de urgência no assunto")
        caps = [w for w in subject.split() if len(w) >= 4 and w.isupper()]
        if len(caps) >= 2:
            score += 10
            reasons.append("Assunto com palavras em maiúsculas (urgência artificial)")
    if body:
        matches = _PHISHING_KW_RE.findall(body)
        if matches:
            unique = list(dict.fromkeys(m.lower() for m in matches))
            score += min(25, len(unique) * 5)
            reasons.append(f"Palavras-chave suspeitas no corpo: {', '.join(unique[:5])}")
    return min(score, 55), reasons


def extract_text_from_html(raw: str) -> str:
    if not raw:
        return ""
    if not _HAS_BS4:
        return re.sub(r"<[^>]+>", " ", raw).strip()
    try:
        soup = BeautifulSoup(raw, "lxml")
        for tag in soup(["script", "style", "meta", "link"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        try:
            return BeautifulSoup(raw, "html.parser").get_text(separator=" ", strip=True)
        except Exception:
            return raw


def run_yara(text: str) -> tuple[int, list[str]]:
    if not _HAS_YARA or not _yara_rules or not text:
        return 0, []
    score = 0
    matched = []
    try:
        for match in _yara_rules.match(data=text.encode("utf-8", errors="replace")[:65535]):
            sev = match.meta.get("severity", "medium")
            pts = {"critical": 45, "high": 30, "medium": 20}.get(sev, 20)
            score += pts
            matched.append(match.rule)
    except Exception as e:
        logger.warning("YARA scan falhou: %s", e)
    return min(score, 80), matched


def run_ner(text: str, sender_domain: str) -> tuple[int, list[str], list[str]]:
    if not text or not sender_domain:
        return 0, [], []
    brands = []
    if _HAS_SPACY and _nlp:
        try:
            for ent in _nlp(text[:5000]).ents:
                if ent.label_ in ("ORG", "PRODUCT", "BRAND"):
                    for brand in _BRAND_NER_MAP:
                        if brand.lower() in ent.text.lower() and brand not in brands:
                            brands.append(brand)
        except Exception:
            pass
    for m in _BRAND_REGEX.finditer(text[:5000]):
        brand = m.group(0)
        for known in _BRAND_NER_MAP:
            if known.lower() == brand.lower() and known not in brands:
                brands.append(known)
    if not brands:
        return 0, [], []
    score = 0
    reasons = []
    legit = any(
        sender_domain == od.lower() or sender_domain.endswith("." + od.lower())
        for brand in brands
        for od in _BRAND_NER_MAP.get(brand, [])
    ) or any(esp in sender_domain for esp in _LEGIT_ESPS)
    if not legit:
        score = 25 * min(len(brands), 2)
        reasons.append(f"NER: email menciona marca(s) '{', '.join(brands[:3])}' mas remetente é '{sender_domain}'")
    return min(score, 50), brands, reasons


_SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cam", ".icu"}
_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly", "rb.gy", "short.link"}
_SUSPICIOUS_HOSTING = {"ngrok.io", "ngrok-free.app", "netlify.app", "github.io", "vercel.app", "pages.dev", "glitch.me", "replit.co", "000webhost.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app"}


def analyze_url_local(url: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    try:
        p = urlparse(url)
        d = (p.hostname or "").lower().lstrip("www.")
    except Exception:
        return 0, []
    if not d:
        return 0, []
    try:
        ipaddress.ip_address(d)
        return 40, [f"URL usa endereço IP: {d}"]
    except ValueError:
        pass
    for tld in _SUSPICIOUS_TLDS:
        if d.endswith(tld):
            score += 25
            reasons.append(f"TLD suspeito: {tld}")
            break
    for host in _SUSPICIOUS_HOSTING:
        if host in d:
            score += 30
            reasons.append(f"Hosting suspeito: {host}")
            break
    if d in _SHORTENERS:
        score += 20
        reasons.append(f"Encurtador: {d}")
    if "@" in url.split("?")[0]:
        score += 40
        reasons.append("URL contém '@'")
    if d.split(".")[0].count("-") >= 3:
        score += 20
        reasons.append("Muitos hífens")
    if len(d) > 40:
        score += 15
        reasons.append("Domínio muito longo")
    path = (p.path or "") + " " + (p.query or "")
    phishing_words = ["login", "signin", "account", "verify", "confirm", "secure", "update", "banking", "password"]
    found = [w for w in phishing_words if w in path]
    if len(found) >= 2:
        score += 20
        reasons.append(f"Palavras de phishing no URL: {', '.join(found[:3])}")
    if url.startswith("http://"):
        score += 10
        reasons.append("URL usa HTTP")
    return min(100, score), reasons


_BRAND_DOMAINS_TYPO = {
    "bai.ao": "BAI", "bfa.ao": "BFA", "bic.ao": "BIC", "bpc.ao": "BPC",
    "atlantico.ao": "Banco Atlântico", "standardbank.ao": "Standard Bank",
    "unitel.ao": "Unitel", "movicel.ao": "Movicel", "africell.ao": "Africell",
    "multicaixa.ao": "Multicaixa", "emis.ao": "EMIS",
    "paypal.com": "PayPal", "amazon.com": "Amazon",
    "microsoft.com": "Microsoft", "apple.com": "Apple",
    "netflix.com": "Netflix", "google.com": "Google",
    "dhl.com": "DHL", "facebook.com": "Facebook",
}


def _lev(s1, s2):
    if len(s1) < len(s2):
        return _lev(s2, s1)
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
    if not domain:
        return False, "", ""
    d = domain.lower().lstrip("www.")
    if d in _BRAND_DOMAINS_TYPO:
        return False, "", ""
    for brand_d, brand_name in _BRAND_DOMAINS_TYPO.items():
        if 0 < _lev(d, brand_d) <= 2:
            return True, brand_name, brand_d
        if brand_d.split(".")[0] in d and d != brand_d and len(brand_d.split(".")[0]) >= 4:
            return True, brand_name, brand_d
    return False, "", ""


def check_display_name_spoofing(sender: str) -> tuple[bool, str]:
    if not sender or "@" not in sender or "<" not in sender:
        return False, ""
    try:
        display = sender[:sender.index("<")].strip().strip('"').lower()
        dom = sender[sender.index("<") + 1:].strip(">").strip().split("@")[-1].lower()
    except Exception:
        return False, ""
    if any(esp in dom for esp in _LEGIT_ESPS):
        return False, ""
    for brand, officials in _BRAND_NER_MAP.items():
        if any(word in display for word in brand.lower().split() if len(word) >= 4):
            if not any(dom == od.lower() or dom.endswith("." + od.lower()) for od in officials):
                return True, brand
    return False, ""


def check_homoglyph_domain(domain: str) -> tuple[bool, str]:
    if not domain:
        return False, ""
    try:
        ascii_ver = unicodedata.normalize("NFKD", domain).encode("ascii", "ignore").decode("ascii").lower()
        if ascii_ver != domain.lower():
            for brand_d, brand_name in _BRAND_DOMAINS_TYPO.items():
                if _lev(ascii_ver, brand_d) <= 1:
                    return True, brand_name
    except Exception:
        pass
    return False, ""


def extract_sender_domain(sender: str) -> str:
    if not sender:
        return ""
    if "<" in sender:
        m = re.search(r"<[^>]*@([^>]+)>", sender)
        if m:
            return m.group(1).strip().lower()
    if "@" in sender:
        return sender.split("@")[-1].strip(">").strip().lower()
    return ""


def is_legit_sender(domain: str) -> bool:
    if not domain:
        return False
    if domain in _KNOWN_SERVICES:
        return True
    return any(domain.endswith("." + k) for k in _KNOWN_SERVICES) or any(esp in domain for esp in _LEGIT_ESPS)


# ─── Extração robusta de URLs ─────────────────────────────────────

def extract_urls(text: str) -> list[str]:
    """Extrai URLs de um texto usando duas estratégias."""
    # Estratégia 1: regex curada
    urls = URL_RE.findall(text)
    if urls:
        return list(set(urls))

    # Estratégia 2: fallback mais permissivo
    urls = URL_RE_FALLBACK.findall(text)
    if urls:
        return list(set(urls))

    # Estratégia 3: procurar qualquer string que comece com http
    urls = re.findall(r"https?://[^\s>\"')\]]*", text)
    return list(set(urls))


# ═══════════════════════════════════════════════════════════════════
# PIPELINE PRINCIPAL
# ═══════════════════════════════════════════════════════════════════

async def hybrid_analyze_email(
    sender: str,
    headers: str,
    body: str | None,
    *,
    run_external_apis: bool = True,
    timeout_total: float = 55.0,
) -> HybridResult:
    t_start = time.monotonic()
    sender = (sender or "").strip()
    body = body or ""
    headers_str = headers or ""
    domain = extract_sender_domain(sender)
    is_legit = is_legit_sender(domain)

    result = HybridResult(sender=sender, domain=domain)

    # ── Extrair assunto de forma fiável ───────────────────────────
    subject = ""
    # Tentar JSON (vem do gmail_hook)
    try:
        hdrs = json.loads(headers_str)
        subject = hdrs.get("subject", "")
    except Exception:
        # Tentar linha "Subject: ..." em texto plano
        m = re.search(r"(?i)^subject:\s*(.+)$", headers_str, re.MULTILINE)
        if m:
            subject = m.group(1).strip()
        # Se ainda vazio, usar os primeiros 200 caracteres como assunto (fallback)
        if not subject and body:
            subject = body[:200].replace("\n", " ")

    result.subject = subject
    logger.debug("Assunto extraído: %s", subject)

    # Combinar assunto + corpo para análise
    full_body = (subject + "\n" + body) if subject else body
    clean_body = extract_text_from_html(body) if body else ""

    # ── Extrair URLs do assunto + corpo ───────────────────────────
    urls_in_body = extract_urls(full_body)
    if not urls_in_body and subject:
        # Se não encontrou no conjunto, tenta extrair só do assunto
        urls_in_body = extract_urls(subject)

    logger.info("URLs encontradas: %s", urls_in_body)

    # CAMADA 0: Palavras-chave
    kw_score, kw_reasons = analyze_keywords(subject, clean_body or body)
    result.layers["keywords"] = {"score": kw_score, "reasons": kw_reasons}
    if kw_score > 0:
        if is_legit:
            kw_score //= 3
        result.score += kw_score
        result.reasons.extend(kw_reasons)

    # CAMADA 1: YARA
    try:
        loop = asyncio.get_running_loop()
        yara_score, yara_matches = await asyncio.wait_for(
            loop.run_in_executor(None, run_yara, full_body + "\n" + headers_str),
            timeout=3.0,
        )
        result.yara_matched = yara_matches
        result.layers["yara"] = {"score": yara_score, "matches": yara_matches}
        if yara_score > 0:
            if is_legit:
                yara_score //= 3
            result.score += yara_score
            if yara_matches:
                result.reasons.append(f"YARA: {len(yara_matches)} regra(s) activada(s): {', '.join(yara_matches)}")
    except Exception as e:
        result.layers["yara"] = {"error": str(e)}

    # CAMADA 2: NER
    try:
        ner_score, ner_brands, ner_reasons = await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(None, run_ner, full_body, domain),
            timeout=5.0,
        )
        result.ner_brands = ner_brands
        result.layers["ner"] = {"score": ner_score, "brands": ner_brands}
        if ner_brands:
            result.brand_detected = ner_brands[0]
        if ner_score > 0 and not is_legit:
            result.score += ner_score
            result.reasons.extend(ner_reasons)
    except Exception as e:
        result.layers["ner"] = {"error": str(e)}

    # CAMADA 3: Heurísticas locais
    max_url_score = 0
    for url in urls_in_body[:5]:
        u_score, u_reasons = analyze_url_local(url)
        if u_score > max_url_score:
            max_url_score = u_score
        if u_score >= 30:
            result.reasons.extend(u_reasons)
    if max_url_score > 0 and not is_legit:
        result.score += max_url_score // 2

    if not is_legit:
        is_typo, typo_brand, typo_domain = check_typosquatting(domain)
        if is_typo:
            result.is_typosquat = True
            result.score += 40
            result.reasons.append(f"Typosquatting: '{domain}' imita '{typo_brand}' ({typo_domain})")
        is_homoglyph, homoglyph_brand = check_homoglyph_domain(domain)
        if is_homoglyph:
            result.is_typosquat = True
            result.score += 50
            result.reasons.append(f"Homoglyph spoofing: '{domain}' imita '{homoglyph_brand}'")

    is_spoofed, spoofed_brand = check_display_name_spoofing(sender)
    if is_spoofed:
        result.is_spoofed = True
        result.score += 35
        result.reasons.append(f"Display-name spoofing: '{spoofed_brand}' de '{domain}'")

    # CAMADA 4: ML (Groq)
    try:
        from backend.services.ml_classifier import classify_with_groq
        ml = dict(await asyncio.wait_for(classify_with_groq(clean_body or headers_str, "email"), timeout=12.0))
        result.ml = ml
        ml_score = int(ml.get("ml_score", 0))
        result.layers["ml"] = {"score": ml_score}
        if ml.get("reasoning"):
            result.reasons.insert(0, f"IA: {ml['reasoning']}")
        if is_legit and ml_score < 30 and result.score < 50:
            result.score = min(result.score, 20)
        elif ml_score >= 70:
            result.score = max(result.score, ml_score - 5)
        elif ml_score >= 50:
            result.score = max(result.score, ml_score)
    except asyncio.TimeoutError:
        result.layers["ml"] = {"error": "timeout"}
    except ImportError:
        pass
    except Exception as e:
        result.layers["ml"] = {"error": str(e)}

    # CAMADA 5: DNS (apenas para domínios não legítimos)
    if not is_legit and domain:
        try:
            from backend.services.dns_check import check_spf_dkim
            dns_r = dict(await asyncio.wait_for(check_spf_dkim(domain), timeout=5.0))
            result.dns = dns_r
            result.spf_pass = dns_r.get("spf") == "pass"
            result.dkim_pass = dns_r.get("dkim") == "pass"
            result.dmarc_pass = dns_r.get("dmarc") == "pass"
            result.layers["dns"] = dns_r
            if not result.spf_pass:
                result.score += 10
                result.reasons.append(f"SPF falhou para '{domain}'")
            if not result.dkim_pass:
                result.score += 5
                result.reasons.append(f"DKIM não verificado para '{domain}'")
            if not result.dmarc_pass:
                result.score += 5
                result.reasons.append(f"DMARC ausente/falhou para '{domain}'")
        except Exception:
            pass

    # CAMADA 6: APIs EXTERNAS — AGORA COM URLs GARANTIDOS
    if run_external_apis and (urls_in_body or domain):
        logger.info("🔌 Iniciando APIs externas para %d URLs", len(urls_in_body))
        api_results = await _run_external_apis(urls=urls_in_body[:3], domain=domain)
        result.layers["external_apis"] = api_results
        result.urls_checked = api_results.get("url_details", [])
        ext_score = api_results.get("score", 0)
        ext_reasons = api_results.get("reasons", [])
        apis_pos = api_results.get("apis_positive", 0)
        if ext_score > 0:
            result.score = max(result.score, result.score + ext_score // 2)
            result.reasons.extend(ext_reasons)
        if apis_pos >= 2:
            result.score = max(result.score, 80)
        logger.info("🔌 APIs externas concluídas: score=%d, apis_positive=%d", ext_score, apis_pos)

    # Anti-FP
    if is_legit and result.score < 50 and not result.is_typosquat and not result.is_spoofed:
        result.score = min(result.score, 25)

    result.score = max(0, min(100, result.score))
    result.reasons = list(dict.fromkeys(result.reasons))

    if result.score >= 60:
        result.verdict = "NÃO SEGURO"
    elif result.score >= 30:
        result.verdict = "SUSPEITO"
    else:
        result.verdict = "SEGURO"

    logger.info("✅ Análise híbrida concluída: score=%d, verdict=%s, tempo=%.1fs", result.score, result.verdict, time.monotonic() - t_start)
    return result


# ═══════════════════════════════════════════════════════════════════
# APIs EXTERNAS – sem timeout global, com logs detalhados
# ═══════════════════════════════════════════════════════════════════

async def _run_external_apis(urls: list[str], domain: str) -> dict:
    from backend.services.external_apis import (
        check_virustotal, check_safe_browsing, check_urlscan_existing,
        phishing_blacklist_check, check_abuseipdb, check_dnsbl_sync,
    )

    score = 0
    reasons = []
    url_details = []
    apis_positive = 0

    # Resolver IP do domínio
    target_ip = None
    if domain:
        try:
            target_ip = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, socket.gethostbyname, domain), timeout=2.0
            )
        except Exception:
            pass

    tasks: dict[str, asyncio.Task] = {}
    if urls:
        u = urls[0]
        tasks["vt"] = asyncio.create_task(asyncio.wait_for(check_virustotal(u), timeout=15))
        tasks["gsb"] = asyncio.create_task(asyncio.wait_for(check_safe_browsing(u), timeout=15))
        tasks["urlscan"] = asyncio.create_task(asyncio.wait_for(check_urlscan_existing(u), timeout=15))
        tasks["blacklist"] = asyncio.create_task(asyncio.wait_for(phishing_blacklist_check(u), timeout=20))

    if target_ip:
        tasks["abuseipdb"] = asyncio.create_task(asyncio.wait_for(check_abuseipdb(target_ip), timeout=12))
    if domain:
        tasks["dnsbl"] = asyncio.create_task(
            asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, check_dnsbl_sync, domain), timeout=5)
        )

    if not tasks:
        return {"score": 0, "reasons": [], "apis_positive": 0, "url_details": []}

    # Aguardar cada task terminar (sem timeout global)
    for name, task in tasks.items():
        try:
            await task
        except Exception:
            logger.debug("API %s falhou", name)

    # Recolher resultados
    api_results = {}
    for name, task in tasks.items():
        if task.done() and not task.cancelled():
            try:
                api_results[name] = task.result()
            except Exception as e:
                logger.debug("API %s erro: %s", name, e)
                api_results[name] = {}
        else:
            api_results[name] = {}

    logger.info("APIs concluídas: %s", list(api_results.keys()))

    # Processar cada API
    vt = api_results.get("vt", {})
    if isinstance(vt, dict):
        mal = int(vt.get("malicious", 0))
        if mal >= 10:
            score = max(score, 90)
            reasons.append(f"VirusTotal: {mal} motores CRÍTICO")
            apis_positive += 1
        elif mal >= 5:
            score = max(score, 80)
            reasons.append(f"VirusTotal: {mal} motores ALTO")
            apis_positive += 1
        elif mal >= 3:
            score = max(score, 65)
            reasons.append(f"VirusTotal: {mal} motores maliciosos")
            apis_positive += 1
        elif mal >= 2:
            score = max(score, 50)
            reasons.append(f"VirusTotal: {mal} motores maliciosos")
        elif mal == 1:
            score = max(score, 25)
            reasons.append("VirusTotal: 1 motor (inconclusivo)")

    gsb = api_results.get("gsb", {})
    if isinstance(gsb, dict) and gsb.get("threat"):
        score = max(score, 85)
        reasons.append(f"Google Safe Browsing: AMEAÇA detectada ({', '.join(gsb.get('types', []))})")
        apis_positive += 1

    urlscan = api_results.get("urlscan", {})
    if isinstance(urlscan, dict):
        if urlscan.get("malicious"):
            score = max(score, 60)
            reasons.append("URLScan.io: URL maliciosa")
            apis_positive += 1
        elif urlscan.get("score", 0) >= 70:
            score = max(score, 50)
            reasons.append(f"URLScan.io: risco {urlscan['score']}")

    abuse = api_results.get("abuseipdb", {})
    if isinstance(abuse, dict):
        ab_score = int(abuse.get("abuse_score", 0))
        if ab_score >= 80:
            score = max(score, 70)
            reasons.append(f"AbuseIPDB: IP {target_ip} score {ab_score}")
            apis_positive += 1
        elif ab_score >= 50:
            score = max(score, 45)
            reasons.append(f"AbuseIPDB: IP suspeito ({ab_score})")

    dnsbl = api_results.get("dnsbl", {})
    if isinstance(dnsbl, dict) and dnsbl.get("hits"):
        score = max(score, 55)
        reasons.append(f"DNSBL: {', '.join(dnsbl['hits'][:2])}")
        apis_positive += 1

    bl = api_results.get("blacklist", {})
    if isinstance(bl, dict):
        if bl.get("blacklisted"):
            reasons.extend(bl.get("reasons", []))
            score = max(score, bl.get("score", 90))
            apis_positive += 2
            logger.warning("BLACKLIST HIT: %s", bl.get("reasons", []))
        elif bl.get("score", 0) > 0:
            score = max(score, bl.get("score", 0))
            reasons.extend(bl.get("reasons", []))

    if apis_positive >= 2:
        score = max(score, 80)
        reasons.append(f"CONSENSO: {apis_positive} APIs confirmam ameaça")

    if urls:
        url_details.append({"url": urls[0], "vt": vt, "gsb": gsb, "urlscan": urlscan, "blacklist": bl, "score": score})

    return {"score": min(100, score), "reasons": reasons, "apis_positive": apis_positive, "url_details": url_details}
