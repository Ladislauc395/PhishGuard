import sys
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Garante que o Python encontra as pastas core e services
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from services.heuristic_engine import HeuristicEngine
from core.database import init_db

app = FastAPI(title="PhishGuard API")
engine = HeuristicEngine()

@app.on_event("startup")
async def on_startup():
    try:
        await init_db()
        print("\n✅ [DATABASE] Conexão com PostgreSQL ativa!")
    except Exception as e:
        print(f"\n❌ [DATABASE] Erro ao conectar: {e}")

class URLRequest(BaseModel):
    url: str

@app.post("/api/analyze/url")
async def analyze_url(request: URLRequest):
    score, reasons = await engine.analyze_url(request.url)
    verdict = "🔴 NÃO SEGURO" if score >= 60 else "✅ SEGURO"
    reasons_str = ", ".join(reasons) if reasons else "Nenhuma ameaça óbvia"
    return {
        "url": request.url, 
        "score": score, 
        "verdict": verdict, 
        "reasons": reasons_str
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
