from dataclasses import dataclass, field
from typing import Any


@dataclass
class AnalysisInput:
    """Normalized input provided to the security engine."""

    content: str
    source: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Final security analysis result."""

    status: str
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "indicators": self.indicators,
        }