from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        description="URL, domain, IP address, or other security target to analyze.",
    )


class AnalyzeResponse(BaseModel):
    status: Literal["completed"] = "completed"
    target: str
    risk_level: Literal["low", "medium", "high", "critical", "unknown"]
    score: int = Field(..., ge=0, le=100)
    message: str