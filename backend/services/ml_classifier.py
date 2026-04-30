"""Classificador ML usando Groq LLM."""
from __future__ import annotations
import json
import logging
from typing import TypedDict
import httpx
from backend.core.config import settings

logger = logging.getLogger(__name__)

# ─── Keywords Angola: separadas por FUNÇÃO ───────────────────────
#
# PROBLEMA ANTERIOR: "unitel", "prémio", "parabéns" eram keywords que
# aumentavam o score automaticamente. Mas:
#   - A Unitel envia promoções e sorteios REAIS
#   - "Parabéns, ganhou" pode ser legítimo vindo de unitel.ao
#   - A keyword serve apenas para IDENTIFICAR o contexto angolano,
#     não para pontuar suspeita
#
# Solução: separar em três grupos:
#   CONTEXT_KEYWORDS  → identificam que é mensagem angolana (sem score)
#   SUSPICIOUS_COMBOS → combinações que SÓ aparecem em phishing
#   CREDENTIAL_WORDS  → pedido de dados sensíveis (alta suspeita)

# Apenas identificam que a mensagem é do contexto angolano — sem score
# NOTA: "nif" (número de identificação fiscal) e "kz" (kwanza) são palavras
# comuns em emails angolanos legítimos — NÃO devem pontuar sozinhos.
ANGOLA_CONTEXT_KEYWORDS = [
    "multicaixa express", "multicaixa", "bai directo", "bai net",
    "unitel", "movicel", "africell",
    "kz", "kwanzas", "kwanza",
    "nif",  # número de identificação fiscal — contexto angolano normal
    "bfa net", "bpc", "bic net", "sonangol", "taag",
    "emis",
]

# Combos que praticamente só existem em phishing
# (menção à marca + acção urgente numa só mensagem)
PHISHING_COMBO_KEYWORDS = [
    "actualização de conta", "atualização de conta",
    "conta bloqueada", "verificar conta",
    "suspensa", "suspenso",
    "clique aqui", "click here",
    "aceder agora", "aceda já",
    "confirme os seus dados", "introduza o seu pin",
    "senha expirada", "palavra-passe expirada",
    "acesso suspenso", "conta suspensa",
    "reactivação de conta", "login não autorizado",
]

# Pedido explícito de credenciais/dados financeiros
# REMOVIDOS: "nif" e "kz" — são termos angolanos normais, não credenciais isoladas
CREDENTIAL_KEYWORDS = [
    "pin", "senha", "password", "palavra-passe",
    "cvv", "iban", "número de conta", "cartão de débito",
    "número do cartão", "código de acesso",
]

# Para manter compatibilidade com código que importa ANGOLA_KEYWORDS
ANGOLA_KEYWORDS = ANGOLA_CONTEXT_KEYWORDS + PHISHING_COMBO_KEYWORDS


class MLResult(TypedDict):
    ml_score: int
    is_phishing: bool
    confidence: float
    keywords_found: list[str]
    reasoning: str


# ─── System prompt melhorado ─────────────────────────────────────
#
# Explicitamente diz ao modelo que promoções e sorteios legítimos existem
# e que a presença de uma marca não é suficiente para classificar como phishing.

SYSTEM_PROMPT = """Você é um analista de segurança especializado em phishing/smishing em Angola.

CONTEXTO ANGOLA:
- Bancos reais: BAI, BFA, BIC, BPC, Standard Bank Angola, Multicaixa Express, EMIS
- Operadoras reais: Unitel, Movicel, Africell
- Estas empresas ENVIAM promoções, sorteios e notificações LEGÍTIMAS.
  Um email/SMS da Unitel sobre um sorteio ou promoção NÃO é automaticamente phishing.
- "NIF" (número de identificação fiscal) é um termo NORMAL em Angola — não é suspeito sozinho.
- "kz" ou "kwanza" são apenas a moeda angolana — não são suspeitos.

CRITÉRIOS DE PHISHING (devem ser avaliados EM CONJUNTO, não isolados):
  1. Pede SIMULTANEAMENTE: credenciais (senha, PIN, código de cartão) + urgência
  2. Urgência artificial: "clique agora ou perde", "24 horas", "conta bloqueada"
  3. Link suspeito: URL que NÃO corresponde ao domínio oficial da marca
  4. Remetente suspeito: domínio que IMITA a marca mas não é o oficial
  5. Pedido de pagamento inesperado ou transferência não solicitada
  6. Pede NIF apenas quando combinado com outros sinais de fraude

NÃO é phishing apenas por:
  - Mencionar o nome de uma marca (Unitel, BAI, Google, etc.)
  - Anunciar prémios, sorteios ou promoções (as marcas fazem isso legitimamente)
  - Usar palavras em português ou kimbundu
  - Mencionar NIF, kz, kwanza (termos angolanos normais)
  - Ter um link (o link tem de ser analisado separadamente por APIs)
  - Ser um email de confirmação/boas-vindas de um serviço

Retorne SOMENTE JSON válido:
{"ml_score": int 0-100, "is_phishing": bool, "confidence": float 0-1, "reasoning": "explicação curta em português"}"""


async def classify_with_groq(text: str, channel: str = "sms") -> MLResult:
    text = (text or "").strip()

    # Encontrar keywords de contexto (não pontuam — servem para enriquecer o prompt)
    context_kw  = [k for k in ANGOLA_CONTEXT_KEYWORDS if k.lower() in text.lower()]
    phishing_kw = [k for k in PHISHING_COMBO_KEYWORDS if k.lower() in text.lower()]
    cred_kw     = [k for k in CREDENTIAL_KEYWORDS if k.lower() in text.lower()]
    all_kw      = list(dict.fromkeys(context_kw + phishing_kw + cred_kw))

    if not text:
        return _heuristic_fallback("", all_kw, phishing_kw, cred_kw)

    if not settings.GROQ_API_KEY:
        return _heuristic_fallback(text, all_kw, phishing_kw, cred_kw)

    # Modelos Groq actuais (Abril 2026). Tentamos em ordem.
    models_to_try = [
        settings.GROQ_MODEL,
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "llama3-70b-8192",
    ]
    seen = set()
    models_to_try = [m for m in models_to_try if not (m in seen or seen.add(m))]

    # Enriquecer o prompt com contexto para o modelo
    context_note = ""
    if context_kw:
        context_note = f"\nMarcas/contexto detectado: {', '.join(context_kw)}"
    if phishing_kw:
        context_note += f"\nPadrões suspeitos detectados: {', '.join(phishing_kw)}"
    if cred_kw:
        context_note += f"\nPedido de credenciais detectado: {', '.join(cred_kw)}"

    last_error = None
    for model in models_to_try:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.GROQ_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "response_format": {"type": "json_object"},
                        "temperature": 0.1,
                        "max_tokens": 300,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user",
                             "content": f"Canal: {channel}{context_note}\n\nMensagem:\n{text[:3500]}"},
                        ],
                    },
                )
                if resp.status_code == 400:
                    last_error = resp.text[:200]
                    logger.warning("Groq 400 com modelo %s: %s", model, last_error)
                    continue
                resp.raise_for_status()
                data    = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed  = json.loads(content)
                logger.info("✅ Groq OK modelo=%s", model)
                return MLResult(
                    ml_score=int(parsed.get("ml_score", 0)),
                    is_phishing=bool(parsed.get("is_phishing", False)),
                    confidence=float(parsed.get("confidence", 0.5)),
                    keywords_found=all_kw,
                    reasoning=str(parsed.get("reasoning", "")),
                )
        except Exception as e:
            last_error = str(e)
            logger.warning("Groq modelo %s falhou: %s", model, e)
            continue

    logger.warning("Todos os modelos Groq falharam. Último erro: %s", last_error)
    return _heuristic_fallback(text, all_kw, phishing_kw, cred_kw)


def _heuristic_fallback(
    text: str,
    all_kw: list[str],
    phishing_kw: list[str] | None = None,
    cred_kw: list[str] | None = None,
) -> MLResult:
    """
    Fallback heurístico quando o Groq não está disponível.

    LÓGICA CORRIGIDA:
      - Apenas keywords de contexto (marca) sem acção suspeita → score baixo
      - Score sobe apenas quando há combos de phishing OU pedido de credenciais
      - Promoções/sorteios sem pedido de dados → score máximo 25 (SEGURO)
    """
    phishing_kw = phishing_kw or []
    cred_kw     = cred_kw or []
    t           = (text or "").lower()

    score = 0

    # Sinais de phishing reais (não apenas presença de marca)
    has_phishing_combo = len(phishing_kw) > 0
    has_credentials    = len(cred_kw) > 0
    has_link           = "http" in t or "bit.ly" in t or "tinyurl" in t

    urgent = any(w in t for w in [
        "urgente", "imediato", "24 horas", "acção necessária",
        "ação necessária", "bloqueada", "suspensa", "suspenso",
        "expira", "último aviso",
    ])

    # Promoção/sorteio SEM outros sinais suspeitos → legítimo
    is_promo = any(w in t for w in [
        "prémio", "premio", "sorteio", "parabéns", "felicitações",
        "ganhou", "vencedor", "oferta", "promoção", "desconto",
        "campanha", "concurso",
    ])

    if has_phishing_combo:
        score += 15 * len(phishing_kw)

    if has_credentials:
        score += 30

    if urgent and has_phishing_combo:
        score += 20

    if has_link and has_phishing_combo:
        score += 15

    if has_link and has_credentials:
        score += 20

    # Promoção legítima sem pedido de dados → penalidade negativa
    # (cancela parte do score de keywords de contexto)
    if is_promo and not has_credentials and not has_phishing_combo:
        score = min(score, 20)  # promoção pura → no máximo SEGURO

    score = min(100, max(0, score))

    reasoning_parts = []
    if has_phishing_combo:
        reasoning_parts.append(f"padrões suspeitos: {', '.join(phishing_kw[:3])}")
    if has_credentials:
        reasoning_parts.append(f"pedido de credenciais: {', '.join(cred_kw[:2])}")
    if urgent:
        reasoning_parts.append("urgência")
    if is_promo and not has_credentials:
        reasoning_parts.append("promoção sem pedido de dados")
    if not reasoning_parts:
        reasoning_parts.append("sem sinais de phishing detectados")

    return MLResult(
        ml_score=score,
        is_phishing=score >= 70,
        confidence=0.65,
        keywords_found=all_kw,
        reasoning=f"Heurística: {'; '.join(reasoning_parts)}",
    )
