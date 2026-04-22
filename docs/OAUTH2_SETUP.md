# OAuth2 Setup (Google Cloud Console) - Preparação para Fase 2

> Este guia prepara credenciais Google OAuth2 para integração futura (login social, Gmail API, etc.).

## 1) Criar projeto no Google Cloud

1. Aceda a: https://console.cloud.google.com/
2. Clique em **Select a project** → **New Project**.
3. Defina nome (ex.: `phishguard-prod`) e crie.

## 2) Configurar OAuth consent screen

1. Menu lateral: **APIs & Services** → **OAuth consent screen**.
2. Escolha tipo **External** (ou Internal se for workspace empresarial).
3. Preencha:
   - App name: `PhishGuard`
   - User support email
   - Developer contact info
4. Salve.

## 3) Adicionar scopes (mínimo recomendado)

Para login com Google:
- `openid`
- `email`
- `profile`

Se for usar Gmail API na Fase 2:
- `https://www.googleapis.com/auth/gmail.readonly` (somente leitura)

## 4) Criar credenciais OAuth Client ID

1. Vá a **APIs & Services** → **Credentials**.
2. Clique **Create Credentials** → **OAuth client ID**.
3. Application type: **Web application**.
4. Name: `phishguard-web-client`.
5. Authorized redirect URIs (exemplos):
   - `http://localhost:3000/auth/google/callback` (frontend local)
   - `http://localhost:8000/api/auth/google/callback` (backend local)
6. Clique em **Create**.

## 5) Guardar Client ID e Client Secret

Após criar, copie:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`

Adicionar no `.env` (Fase 2):

```env
GOOGLE_CLIENT_ID=seu_client_id
GOOGLE_CLIENT_SECRET=seu_client_secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/auth/google/callback
```

## 6) Boas práticas de segurança

- Nunca commitar `client_secret` no Git.
- Rotacione credenciais periodicamente.
- Use scopes mínimos necessários.
- Mantenha lista de redirect URIs estritamente controlada.

## 7) Verificação rápida

- Certifique-se que a OAuth Consent Screen está em estado **In production** (ou configure test users).
- Se receber erro `redirect_uri_mismatch`, confira URI exata (incluindo protocolo e porta).
- Se receber `access blocked`, adicione utilizadores de teste no consent screen.
