from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        description="Text or security target to analyze.",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Target cannot be empty or whitespace.")

        return value


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
findings: list[FindingResponse] = Field(default_factory=list)
reasons: list[str] = Field(default_factory=list)
indicators: list[str] = Field(default_factory=list)
    impact: ImpactResponse | None = None
    response: ResponseDecisionResponse | None = None
    verification: VerificationResponse | None = None
