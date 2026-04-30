import re
import base64
import tldextract
from typing import List, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from schemas import (
    LoginForm, LoginField, LoginFieldType,
    PageMetadata, SecurityIndicators, CloneIndicators,
    RedirectInfo
)

# ─── Helpers ──────────────────────────────────────────────────────

def _get_soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def _get_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


# ─── Login Detection ──────────────────────────────────────────────

def _classify_field(el) -> LoginFieldType:
    input_type = (el.get("type") or "text").lower()
    name = (el.get("name") or "").lower()
    placeholder = (el.get("placeholder") or "").lower()
    id_ = (el.get("id") or "").lower()
    combined = f"{name} {placeholder} {id_}"

    if input_type == "password":
        return LoginFieldType.PASSWORD
    if input_type == "submit" or (input_type == "button" and any(
        k in combined for k in ["login", "sign", "entrar", "acesso"]
    )):
        return LoginFieldType.SUBMIT
    if any(k in combined for k in ["email", "e-mail"]):
        return LoginFieldType.EMAIL
    if any(k in combined for k in ["user", "usuario", "login", "cpf", "cnpj", "username"]):
        return LoginFieldType.USERNAME
    if any(k in combined for k in ["otp", "token", "code", "codigo", "2fa"]):
        return LoginFieldType.OTP
    return LoginFieldType.UNKNOWN


def _find_label(soup: BeautifulSoup, el) -> Optional[str]:
    el_id = el.get("id")
    if el_id:
        label = soup.find("label", {"for": el_id})
        if label:
            return label.get_text(strip=True)
    return None


OAUTH_PATTERNS = {
    "google": ["accounts.google", "google.com"],
    "facebook": ["facebook.com"],
    "apple": ["appleid.apple.com"],
    "microsoft": ["login.microsoftonline", "live.com"],
    "github": ["github.com/login"],
    "twitter": ["twitter.com", "x.com"],
}

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify now", "account suspended", "click here immediately",
    "confirm identity", "limited time", "act fast",
    "verify your account", "suspended", "blocked", "compromised",
]


def detect_login_form(html: str, base_url: str = "") -> LoginForm:
    soup = _get_soup(html)
    forms = soup.find_all("form")

    best_form = None
    best_score = 0.0

    for form in forms:
        score = 0.0
        inputs = form.find_all("input")

        has_password = any(i.get("type", "").lower() == "password" for i in inputs)
        has_text = any(i.get("type", "text").lower() in ("text", "email", "tel") for i in inputs)

        if has_password:
            score += 0.6
        if has_text:
            score += 0.2

        action = (form.get("action") or "").lower()
        if any(k in action for k in ["login", "signin", "auth", "entrar"]):
            score += 0.15

        if score > best_score:
            best_score = score
            best_form = form

    if not best_form or best_score < 0.3:
        return LoginForm(detected=False, confidence=0.0)

    fields: List[LoginField] = []
    for inp in best_form.find_all("input"):
        if inp.get("type", "").lower() in ("hidden", "checkbox", "radio"):
            continue

        fields.append(LoginField(
            field_type=_classify_field(inp),
            selector=f"input[name='{inp.get('name', '')}']" if inp.get("name") else "input",
            name=inp.get("name"),
            placeholder=inp.get("placeholder"),
            id=inp.get("id"),
            label=_find_label(soup, inp),
        ))

    # OAuth detection (melhorado)
    oauth_providers = []
    for a in soup.find_all("a", href=True):
        href = a.get("href", "").lower()
        for provider, patterns in OAUTH_PATTERNS.items():
            if any(p in href for p in patterns):
                oauth_providers.append(provider)

    # CAPTCHA
    has_captcha = bool(
        soup.find(attrs={"class": re.compile(r"captcha|recaptcha|hcaptcha", re.I)})
        or soup.find(attrs={"src": re.compile(r"captcha|recaptcha|hcaptcha", re.I)})
    )

    page_text = soup.get_text().lower()
    suspicious = [kw for kw in SUSPICIOUS_KEYWORDS if kw in page_text]

    action_url = best_form.get("action", "")
    if action_url and base_url:
        action_url = urljoin(base_url, action_url)

    return LoginForm(
        detected=True,
        confidence=min(best_score, 1.0),
        action=action_url or None,
        method=(best_form.get("method") or "POST").upper(),
        fields=fields,
        has_password=any(f.field_type == LoginFieldType.PASSWORD for f in fields),
        has_captcha=has_captcha,
        has_oauth=bool(oauth_providers),
        oauth_providers=list(set(oauth_providers)),
        suspicious_indicators=suspicious,
    )


# ─── Metadata ─────────────────────────────────────────────────────

def extract_metadata(html: str, base_url: str = "") -> PageMetadata:
    soup = _get_soup(html)

    def meta(name=None, prop=None):
        tag = soup.find("meta", attrs={"name": name} if name else {"property": prop})
        return tag.get("content") if tag else None

    favicon = None
    icon = soup.find("link", rel=lambda r: r and "icon" in r)
    if icon:
        favicon = urljoin(base_url, icon.get("href", ""))

    canonical = None
    canon = soup.find("link", rel="canonical")
    if canon:
        canonical = canon.get("href")

    html_tag = soup.find("html")

    return PageMetadata(
        title=soup.title.string.strip() if soup.title and soup.title.string else None,
        description=meta(name="description"),
        keywords=meta(name="keywords"),
        favicon=favicon,
        og_title=meta(prop="og:title"),
        og_image=meta(prop="og:image"),
        canonical=canonical,
        language=html_tag.get("lang") if html_tag else None,
    )


# ─── Security ─────────────────────────────────────────────────────

SUSPICIOUS_SCRIPT_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"unescape\s*\(",
    r"atob\s*\(",
    r"fromCharCode",
    r"\\x[0-9a-fA-F]{2}",
]


def analyze_security(html: str, url: str) -> SecurityIndicators:
    parsed = urlparse(url)
    domain = _get_domain(url)
    soup = _get_soup(html)

    scripts = soup.find_all("script", src=True)

    external = []
    for s in scripts:
        src = s.get("src", "")
        if src.startswith("http"):
            if domain not in _get_domain(src):
                external.append(src)

    inline_scripts = "\n".join(s.string or "" for s in soup.find_all("script", src=False))

    suspicious_scripts = []
    has_obfuscated = False

    for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
        if re.search(pattern, inline_scripts):
            suspicious_scripts.append(pattern)
            has_obfuscated = True

    text = html.lower()

    return SecurityIndicators(
        has_ssl=parsed.scheme == "https",
        ssl_valid=parsed.scheme == "https",
        has_privacy_policy="privacy" in text,
        has_terms="terms" in text,
        external_scripts_count=len(external),
        suspicious_scripts=suspicious_scripts,
        has_obfuscated_js=has_obfuscated,
    )


# ─── Clone Indicators ─────────────────────────────────────────────

MAJOR_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "banco do brasil", "bradesco", "itau", "santander", "nubank"
]

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top"}


def analyze_clone_indicators(html: str, url: str) -> CloneIndicators:
    soup = _get_soup(html)
    text = soup.get_text().lower()
    domain = _get_domain(url)

    brands_detected = [b for b in MAJOR_BRANDS if b in text]

    ext = tldextract.extract(url)
    tld = f".{ext.suffix}" if ext.suffix else ""

    # Typosquat melhorado
    typosquat_risk = 0.0
    for brand in MAJOR_BRANDS:
        clean = brand.replace(" ", "")
        dist = _levenshtein(domain, clean)

        if dist <= 1:
            typosquat_risk = max(typosquat_risk, 0.9)
        elif dist <= 2:
            typosquat_risk = max(typosquat_risk, 0.6)

    return CloneIndicators(
        original_domain_referenced=any(b in html.lower() for b in MAJOR_BRANDS),
        brand_names_detected=list(set(brands_detected)),
        logo_urls=[],
        typosquat_risk=typosquat_risk,
        suspicious_tld=tld in SUSPICIOUS_TLDS,
        copied_assets=[],
    )


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (ca != cb)
            ))
        prev = curr
    return prev[-1]


# ─── Redirect ─────────────────────────────────────────────────────

def build_redirect_info(original_url: str, final_url: str, chain: List[str]) -> RedirectInfo:
    return RedirectInfo(
        occurred=original_url != final_url,
        original_url=original_url,
        final_url=final_url,
        chain=chain,
        cross_domain=_get_domain(original_url) != _get_domain(final_url),
        count=max(0, len(chain) - 1),
    )


# ─── Misc ─────────────────────────────────────────────────────────

def encode_screenshot(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def safe_get_text(soup: BeautifulSoup, max_chars: int = 5000) -> str:
    result = []
    total = 0

    for text in soup.stripped_strings:
        if total + len(text) > max_chars:
            break
        result.append(text)
        total += len(text)

    return " ".join(result)
