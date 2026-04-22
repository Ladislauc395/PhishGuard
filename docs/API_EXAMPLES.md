# Exemplos de API - PhishGuard Fase 1

Base URL local:

```text
http://127.0.0.1:8000
```

## 1) Health Check

```bash
curl -X GET "http://127.0.0.1:8000/health"
```

## 2) Análise de URL

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/url" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://ba1.ao/login"
  }'
```

Resposta esperada:

```json
{
  "score": 80,
  "verdict": "NÃO SEGURO",
  "details": {
    "triggered_rule": "TYPOSQUATTING",
    "domain": "ba1.ao"
  },
  "analysis_id": 1,
  "timestamp": "2026-04-22T10:00:00Z"
}
```

## 3) Análise de SMS

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/sms" \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+244900000000",
    "body": "Ganhou um prémio! Clique aqui: http://oferta-segura.ao"
  }'
```

## 4) Análise de Email

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze/email" \
  -H "Content-Type: application/json" \
  -d '{
    "sender": "fraude@example.com",
    "subject": "Atualize a sua conta agora",
    "headers": "Authentication-Results: mx.google.com; spf=fail dkim=fail dmarc=fail\nReceived-SPF: fail",
    "body": "Aceda imediatamente: https://multicaixa-seguro-login.com"
  }'
```

## 5) Estatísticas do dashboard

```bash
curl -X GET "http://127.0.0.1:8000/api/dashboard/stats"
```

Resposta esperada:

```json
{
  "total_analyses": 30,
  "total_safe": 11,
  "total_unsafe": 19,
  "unsafe_rate_percent": 63.33,
  "by_channel": {
    "web": 12,
    "sms": 10,
    "email": 8
  },
  "by_verdict": {
    "SEGURO": 11,
    "NÃO SEGURO": 19
  }
}
```

## 6) Exemplo Python (requests)

```python
import requests

base_url = "http://127.0.0.1:8000"
payload = {"url": "https://bai.ao"}

resp = requests.post(f"{base_url}/api/analyze/url", json=payload, timeout=10)
resp.raise_for_status()
print(resp.json())
```
