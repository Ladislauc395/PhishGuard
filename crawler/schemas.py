from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from enum import Enum


class CrawlRequest(BaseModel):
    url: str = Field(..., description="URL alvo para crawlear")
    timeout: int = Field(default=15000, ge=1000, le=60000, description="Timeout em ms")
    wait_for: Optional[str] = Field(default=None, description="Seletor CSS para aguardar")
    screenshot: bool = Field(default=False, description="Capturar screenshot")
    follow_redirects: bool = Field(default=True, description="Seguir redirecionamentos")


class LoginFieldType(str, Enum):
    USERNAME = "username"
    EMAIL = "email"
    PASSWORD = "password"
    OTP = "otp"
    SUBMIT = "submit"
    UNKNOWN = "unknown"


class LoginField(BaseModel):
    field_type: LoginFieldType
    selector: str
    name: Optional[str] = None
    placeholder: Optional[str] = None
    id: Optional[str] = None
    label: Optional[str] = None


class LoginForm(BaseModel):
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    action: Optional[str] = None
    method: Optional[str] = None
    fields: List[LoginField] = []
    has_password: bool = False
    has_captcha: bool = False
    has_oauth: bool = False
    oauth_providers: List[str] = []
    suspicious_indicators: List[str] = []


class RedirectInfo(BaseModel):
    occurred: bool
    original_url: str
    final_url: str
    chain: List[str] = []
    cross_domain: bool = False
    count: int = 0


class PageMetadata(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    keywords: Optional[str] = None
    favicon: Optional[str] = None
    og_title: Optional[str] = None
    og_image: Optional[str] = None
    canonical: Optional[str] = None
    language: Optional[str] = None


class SecurityIndicators(BaseModel):
    has_ssl: bool = False
    ssl_valid: bool = False
    domain_age_days: Optional[int] = None
    has_privacy_policy: bool = False
    has_terms: bool = False
    external_scripts_count: int = 0
    suspicious_scripts: List[str] = []
    has_obfuscated_js: bool = False


class CloneIndicators(BaseModel):
    """Indicadores estáticos de clone — complementa o BrandVerdict dinâmico."""
    original_domain_referenced: bool = False
    brand_names_detected: List[str] = []
    logo_urls: List[str] = []
    suspicious_tld: bool = False
    copied_assets: List[str] = []


class OfficialDomainCandidate(BaseModel):
    """Candidato a domínio oficial encontrado via busca na web."""
    domain: str
    score: float = Field(ge=0.0, le=1.0)
    occurrences: int
    source_urls: List[str] = []


class BrandVerdict(BaseModel):
    """
    Resultado da análise dinâmica de autenticidade de domínio.
    Substitui a lista estática de marcas — tudo é resolvido em runtime via busca.
    """
    brand_name: Optional[str] = None
    official_domain: Optional[str] = None
    current_domain: str
    is_official: bool = False
    is_impersonation: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    impersonation_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    search_results_used: int = 0
    explanation: str = ""
    official_candidates: List[OfficialDomainCandidate] = []


class CrawlResponse(BaseModel):
    success: bool
    url: str
    status_code: Optional[int] = None
    html: Optional[str] = None
    html_length: int = 0
    text_content: Optional[str] = None
    metadata: PageMetadata = PageMetadata()
    login_form: LoginForm = LoginForm(detected=False, confidence=0.0)
    redirect: RedirectInfo
    security: SecurityIndicators = SecurityIndicators()
    clone_indicators: CloneIndicators = CloneIndicators()
    brand_verdict: Optional[BrandVerdict] = None   # ← detecção dinâmica
    screenshot_base64: Optional[str] = None
    crawl_duration_ms: int = 0
    error: Optional[str] = None
    warnings: List[str] = []


class HealthResponse(BaseModel):
    status: str
    playwright_ready: bool
    version: str = "1.0.0"
 
    