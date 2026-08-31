from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        description="Text or security target to analyze.",
    )


class FindingResponse(BaseModel):
    rule_id: str
    severity: str
    reason: str
    indicator: str


class ImpactResponse(BaseModel):
    level: str
    reasons: list[str] = []


class ResponseDecisionResponse(BaseModel):
    action: str
    reason: str


class VerificationResponse(BaseModel):
    verified: bool
    status: str
    details: str


class AnalyzeResponse(BaseModel):
    status: str
    target: str
    risk_score: int = Field(..., ge=0, le=100)
    verdict: str
    findings: list[FindingResponse] = []
    reasons: list[str] = []
    indicators: list[str] = []
    impact: ImpactResponse | None = None
    response: ResponseDecisionResponse | None = None
    verification: VerificationResponse | None = None
