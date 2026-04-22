# PhishGuard - Backend Fase 1

Backend FastAPI para deteção heurística de phishing (sem ML), focado no contexto angolano.

## 1) Pré-requisitos

- Linux (Ubuntu, Debian ou Fedora)
- Python 3.12+
- Git
- PostgreSQL 14+

## 2) Estrutura do projeto

```bash
phishguard/
├── backend/
│   ├── core/
│   ├── models/
│   ├── routers/
│   ├── services/
│   └── seeds/
├── docs/
├── scripts/
├── requirements.txt
└── .env.example
```

## 3) Instalação do PostgreSQL

### Opção automática (recomendada)

```bash
cd phishguard
chmod +x scripts/setup_postgres.sh
sudo ./scripts/setup_postgres.sh
```

Este script:
- instala PostgreSQL
- inicia o serviço
- cria `phishguard`
- cria `phishguard_user` com permissões necessárias

### Opção manual (se já tiver PostgreSQL)

```bash
sudo -u postgres psql -v ON_ERROR_STOP=1 -f scripts/init_database.sql
```

## 4) Setup Python

```bash
cd phishguard
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 5) Variáveis de ambiente

```bash
cp .env.example .env
```

Edite `.env` se necessário (principalmente `SECRET_KEY` e `DATABASE_URL`).

## 6) Criar tabelas / "migrations" da Fase 1

Na Fase 1, as tabelas são criadas automaticamente no startup da API com `SQLModel.metadata.create_all(...)`.

Para ambientes produtivos, recomenda-se adotar Alembic na Fase 2 para migrations versionadas.

## 7) Seed das marcas angolanas

```bash
python -m backend.seeds.seed_brands
```

Marcas incluídas:
- BAI (`bai.ao`)
- BFA (`bfa.ao`)
- BPC (`bpc.ao`)
- Banco SOL (`bancosol.ao`)
- Multicaixa Express (`multicaixa.ao`)
- Unitel (`unitel.ao`)
- Africell (`africell.ao`)
- Zap (`zap.co.ao`)
- AGT (`agt.gov.ao`)

## 8) Executar o servidor

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

Endpoints principais:
- `POST /api/analyze/url`
- `POST /api/analyze/sms`
- `POST /api/analyze/email`
- `GET /api/dashboard/stats`
- `GET /health`

## 9) Regras de decisão

- `score >= 60` → **NÃO SEGURO**
- `score < 60` → **SEGURO**

Heurísticas implementadas:
1. DNS fail → 100
2. Typosquatting → 80
3. Domínio não oficial com marca detectada → 100
4. SPF/DKIM/DMARC fail + link suspeito → 70
5. SMS com palavras-chave suspeitas + URL → 65

## 10) Teste rápido

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/sms" \
  -H "Content-Type: application/json" \
  -d '{"phone_number":"+244900000000","body":"Ganhou um prémio! Clique aqui: http://ba1.ao"}'
```

Ver exemplos completos em `docs/API_EXAMPLES.md`.
