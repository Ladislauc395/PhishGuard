from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field

class AnalysisResult(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source: str = Field(index=True)
    content: str
    score: int
    verdict: str
    reasons: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
