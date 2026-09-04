from pydantic import BaseModel
from typing import Any


class EmailAnalysisResponse(BaseModel):
    verdict: str
    risk_score: int
    email: dict[str, Any]
    forensics: dict[str, Any]
    iocs: list[Any]
    threat_intelligence: dict[str, Any]
    geolocation: dict[str, Any]
    attribution: dict[str, Any]
    timeline: list[Any]	