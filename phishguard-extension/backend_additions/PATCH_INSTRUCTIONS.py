# ═══════════════════════════════════════════════════════════════
# PATCH PARA backend/main.py — ADICIONAR SUPORTE À EXTENSÃO CHROME
# ═══════════════════════════════════════════════════════════════
#
# Adiciona APENAS duas linhas ao teu main.py existente.
# NÃO modificar o resto do ficheiro.
#
# PASSO 1 — Copiar o router para o backend:
#   cp extension_router.py backend/routers/extension_router.py
#
# PASSO 2 — Adicionar ao backend/main.py (as duas linhas marcadas):
# ───────────────────────────────────────────────────────────────

# ── Adicionar este import junto aos outros imports de routers ──────

from backend.routers.extension_router import router as extension_router

# ── Adicionar este include_router após os outros includes ──────────
# (por exemplo, após a linha que regista o gmail_router)

app.include_router(extension_router, prefix="/extension")  # ← NOVO

# ═══════════════════════════════════════════════════════════════
# Resultado: os seguintes endpoints ficam disponíveis:
#
#   POST /extension/check-url         ← extensão usa este
#   POST /extension/check-urls-batch  ← extensão usa este (links na página)
#   GET  /extension/stats             ← dashboard de uso
#   GET  /extension/health            ← status das APIs
#
# O endpoint /health já existente em main.py NÃO é alterado.
# ═══════════════════════════════════════════════════════════════

# ── Variáveis de ambiente necessárias (.env) ───────────────────────
# Já configuradas no teu projecto:
#
# VIRUSTOTAL_API_KEY=572c256bf4771c8b9806e42963543e2536d47bb16e7133ae1e18426146cb71b7
# ABUSEIPDB_API_KEY=54caca951cb1c96586b8b5d5a1af3c6233cb16afec90d9d0994b44cae2d647bc8640423fe1728507
# URLSCAN_API=019db6f6-b7d9-759f-a0b0-917fff4da65c
# GOOGLE_SAFE_BROWSING_API_KEY=AIzaSyBX4hckCMD-R_mLmcs2x8s8pcyVMMNLAsU
# GOOGLE_CUSTOM_SEARCH_API_KEY=AIzaSyCm-TSbr4mGKv0ua7uwV_6d4nbwTkBlMVM
# GOOGLE_CUSTOM_SEARCH_ENGINE_ID=4460e3fb1ddc44206
#
# Verificar se URLSCAN_API_KEY ou URLSCAN_API está definido no backend/core/config.py:
# Se não existir, adicionar:
#   URLSCAN_API_KEY: str = ""
#   URLSCAN_API: str = ""    ← alternativa usada pelo extension_router

# ── Verificar settings.py / config.py ─────────────────────────────
# Garantir que estes campos existem em backend/core/config.py (Settings):
#
# class Settings(BaseSettings):
#     ...
#     URLSCAN_API_KEY: str = ""          # pode já existir como URLSCAN_API
#     URLSCAN_API: str = ""              # usado em external_apis.py
#     GOOGLE_SAFE_BROWSING_API_KEY: str = ""
#     GOOGLE_CUSTOM_SEARCH_API_KEY: str = ""
#     GOOGLE_CUSTOM_SEARCH_ENGINE_ID: str = ""
