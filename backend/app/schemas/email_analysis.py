from pydantic import BaseModel, Field, field_validator


class AnalyzeEmailRequest(BaseModel):
    raw_email: str = Field(
        ...,
        min_length=1,
        description="Raw RFC-compliant email content to analyze.",
    )

    @field_validator("raw_email")
    @classmethod
    def validate_raw_email(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Raw email cannot be empty or whitespace.")

        return value


class EmailFindingResponse(BaseModel):
    rule_id: str
    severity: str
    reason: str
    indicator: str


class EmailRiskResponse(BaseModel):
    score: int = Field(..., ge=0, le=100)
    level: str
    reasons: list[str] = Field(default_factory=list)


class AnalyzeEmailResponse(BaseModel):
    status: str
    sender: str | None = None
    recipients: list[str] = Field(default_factory=list)
    subject: str | None = None
    risk_score: int = Field(..., ge=0, le=100)
    verdict: str
    findings: list[EmailFindingResponse] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    risk: EmailRiskResponse | None = None