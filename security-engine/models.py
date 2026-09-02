from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityEvent:
    content: str
    source: str = "unknown"
    event_type: str = "text"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedEvent:
    content: str
    source: str
    event_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    severity: str
    reason: str
    indicator: str
    value: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "reason": self.reason,
            "indicator": self.indicator,
            "value": self.value,
        }


@dataclass
class RiskResult:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
        }


@dataclass
class ImpactResult:
    level: str = "UNKNOWN"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "reasons": self.reasons,
        }


@dataclass
class ResponseDecision:
    action: str = "NO_ACTION"
    reason: str = "No response action required."

    def to_dict(self) -> dict[str, str]:
        return {
            "action": self.action,
            "reason": self.reason,
        }


@dataclass
class VerificationResult:
    verified: bool = True
    status: str = "NOT_REQUIRED"
    details: str = "No response action was executed."

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "status": self.status,
            "details": self.details,
        }


@dataclass
class SecurityResult:
    verdict: str
    risk_score: int
    reasons: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk: RiskResult | None = None
    impact: ImpactResult | None = None
    response: ResponseDecision | None = None
    verification: VerificationResult | None = None

    @property
    def status(self) -> str:
        if self.verdict == "SAFE":
            return "SAFE"

        if self.verdict == "SUSPICIOUS":
            if self.risk_score >= 50:
                return "MEDIUM"
            return "LOW"

        if self.verdict == "MALICIOUS":
            return "HIGH"

        if self.verdict == "REJECTED":
            return "REJECTED"

        return "UNKNOWN"

    def __getitem__(self, key: str) -> Any:
        """Support dictionary-style result access."""

        if key == "verdict":
            return self.verdict

        if key == "status":
            return self.status

        if key == "risk_score":
            return self.risk_score

        if key == "reasons":
            return self.reasons

        if key == "indicators":
            return self.indicators

        if key == "findings":
            return self.findings

        if key == "risk":
            return self.risk

        if key == "impact":
            return self.impact

        if key == "response":
            return self.response

        if key == "verification":
            return self.verification

        if key == "valid":
            return self.verdict not in {
                "UNKNOWN",
                "REJECTED",
            }

        if key == "error":
            if self.verdict == "REJECTED":
                return (
                    self.reasons[0]
                    if self.reasons
                    else "Input rejected."
                )

            return None

        raise KeyError(key)

    def get(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """Dictionary-compatible get method."""

        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        """Support dictionary-style membership checks."""

        if not isinstance(key, str):
            return False

        return key in {
            "verdict",
            "status",
            "risk_score",
            "reasons",
            "indicators",
            "findings",
            "risk",
            "impact",
            "response",
            "verification",
            "valid",
            "error",
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert the security result to a dictionary."""

        return {
            "verdict": self.verdict,
            "status": self.status,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "indicators": self.indicators,
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "risk": (
                self.risk.to_dict()
                if self.risk is not None
                else None
            ),
            "impact": (
                self.impact.to_dict()
                if self.impact is not None
                else None
            ),
            "response": (
                self.response.to_dict()
                if self.response is not None
                else None
            ),
            "verification": (
                self.verification.to_dict()
                if self.verification is not None
                else None
            ),
        }


AnalysisInput = NormalizedEvent


@dataclass
class AnalysisResult:
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