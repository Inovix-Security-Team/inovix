from pydantic import BaseModel


class EmailAnalysisResponse(BaseModel):
    verdict: str
    risk_score: int
    email: dict
    forensics: dict
    iocs: list
    threat_intelligence: dict
    geolocation: dict
    attribution: dict
    timeline: list