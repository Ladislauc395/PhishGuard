# PhishGuard Angola — Chrome Extension
## Guia de Instalação e Uso

---

## 🗂️ Estrutura de Ficheiros

```
phishguard-extension/
├── manifest.json           ← Configuração da extensão (MV3)
├── background.js           ← Service Worker: intercept + análise
├── content.js              ← Injecção de overlay + scan de links
├── popup.html / popup.js   ← Interface do botão da extensão
├── block.html              ← Página de bloqueio (phishing confirmado)
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── backend_additions/
    ├── extension_router.py ← Novo router FastAPI (copiar para backend)
    └── PATCH_INSTRUCTIONS.py ← Como integrar no main.py
```

---

## ⚙️ PASSO 1 — Integrar no Backend Existente

### 1.1 Copiar o router

```bash
cp backend_additions/extension_router.py backend/routers/extension_router.py
```

### 1.2 Adicionar ao `backend/main.py`

Adiciona **apenas** estas duas linhas ao teu `main.py` existente:

```python
# Junto aos outros imports de routers:
from backend.routers.extension_router import router as extension_router

# Junto aos outros app.include_router():
app.include_router(extension_router, prefix="/extension")
```

### 1.3 Verificar `backend/core/config.py`

Confirma que estes campos existem na classe `Settings`:

```python
class Settings(BaseSettings):
    # ... campos existentes ...
    URLSCAN_API_KEY: str = ""          # ou URLSCAN_API se já usas esse nome
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    GOOGLE_CUSTOM_SEARCH_API_KEY: str = ""
    GOOGLE_CUSTOM_SEARCH_ENGINE_ID: str = ""
```

### 1.4 Verificar `.env`

```dotenv
VIRUSTOTAL_API_KEY=572c256bf4771c8b9806e42963543e2536d47bb16e7133ae1e18426146cb71b7
ABUSEIPDB_API_KEY=54caca951cb1c96586b8b5d5a1af3c6233cb16afec90d9d0994b44cae2d647bc8640423fe1728507
URLSCAN_API=019db6f6-b7d9-759f-a0b0-917fff4da65c
GOOGLE_SAFE_BROWSING_API_KEY=AIzaSyBX4hckCMD-R_mLmcs2x8s8pcyVMMNLAsU
GOOGLE_CUSTOM_SEARCH_API_KEY=AIzaSyCm-TSbr4mGKv0ua7uwV_6d4nbwTkBlMVM
GOOGLE_CUSTOM_SEARCH_ENGINE_ID=4460e3fb1ddc44206
```

### 1.5 Reiniciar o backend

```bash
uvicorn backend.main:app --reload --port 8000
```

### 1.6 Testar endpoints

```bash
# Health check da extensão
curl http://localhost:8000/extension/health

# Testar análise de URL
curl -X POST http://localhost:8000/extension/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://bai-angola-verificar.xyz/login"}'
```

---

## 🔌 PASSO 2 — Instalar a Extensão no Chrome

### 2.1 Abrir gestão de extensões

1. Abrir o Chrome
2. Ir para: `chrome://extensions/`
3. Activar **"Modo de programador"** (canto superior direito)

### 2.2 Carregar a extensão

1. Clicar em **"Carregar sem compressão"**
2. Seleccionar a pasta `phishguard-extension/`
3. A extensão aparece na barra de ferramentas com ícone 🛡️

### 2.3 Configurar URL da API

1. Clicar no ícone 🛡️ na barra do Chrome
2. Ir ao separador **"Definições"**
3. Verificar que "URL da API PhishGuard" está em `http://localhost:8000`
4. Clicar **"Guardar Definições"**

---

## 🛡️ Como Funciona

### Detecção em Tempo Real

Cada vez que navegas para uma URL:

```
Navegação detectada
       ↓
Verificar cache (10 min TTL)
       ↓
Heurísticas locais (<5ms):
  • Typosquatting (Levenshtein)
  • TLD suspeito (.xyz, .tk, .ml...)
  • Domínio com IP directo
  • URL com @ no caminho
       ↓
Score < 15? → SEGURO (sem APIs externas)
       ↓
APIs externas em paralelo (~5s):
  • VirusTotal
  • Google Safe Browsing
  • URLScan.io
  • AbuseIPDB
  • DNSBL (Spamhaus, SURBL)
       ↓
Score ≥ 60 → BLOQUEADO (página de aviso)
Score 30-59 → SUSPEITO (overlay de aviso)
Score < 30  → SEGURO
```

### Scan de Links na Página

- Detecta automaticamente links suspeitos em qualquer página
- Marca links perigosos com badge vermelho **PHISHING**
- Marca links suspeitos com badge laranja **SUSPEITO**

### Popup da Extensão

- Score e veredicto da página actual em tempo real
- Estatísticas de verificações (total, suspeitas, bloqueadas)
- Histórico das últimas 30 URLs verificadas
- Status da API (online/offline)

---

## 🎨 Páginas da Extensão

### Página de Bloqueio (`block.html`)
- Mostrada quando URL tem score ≥ 60
- Score de risco com cor vermelha
- Lista de razões específicas detectadas
- Tags categorizando o tipo de ataque
- Botão "Voltar para segurança"
- Botão de override para utilizadores avançados

### Overlay de Aviso
- Injectado na página quando score está entre 30-59
- Não redirige — apenas avisa
- Utilizador pode fechar e continuar

---

## 🔧 Configurações Disponíveis

| Definição | Default | Descrição |
|-----------|---------|-----------|
| Protecção activa | ✅ | Liga/desliga toda a protecção |
| Threshold bloqueio | 60 | Score mínimo para bloquear |
| Threshold aviso | 30 | Score mínimo para avisar |
| Verificar links | ✅ | Scan de links na página |
| Notificações | ✅ | Notificações do sistema |
| URL da API | localhost:8000 | Backend PhishGuard |

---

## 📊 Endpoints da API

| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/extension/check-url` | POST | Verificar 1 URL |
| `/extension/check-urls-batch` | POST | Verificar até 20 URLs |
| `/extension/stats` | GET | Estatísticas de uso |
| `/extension/health` | GET | Status das APIs |

---

## ❓ Resolução de Problemas

### API offline no popup
- Verificar se o backend está a correr: `curl http://localhost:8000/health`
- Verificar a URL da API nas Definições da extensão

### Extensão não carrega
- Verificar que o `manifest.json` está correcto
- Verificar a consola em `chrome://extensions/` → "Erros"

### Muitos falsos positivos
- Aumentar o threshold de bloqueio para 70 nas Definições
- Aumentar o threshold de aviso para 40

### APIs externas lentas
- O timeout global é 10s — normal para primeira verificação
- Resultados são cacheados por 10 minutos
