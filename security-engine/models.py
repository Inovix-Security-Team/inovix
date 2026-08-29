from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityEvent:
    """Raw security event submitted to the engine."""

    content: str
    source: str = "unknown"
    event_type: str = "text"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedEvent:
    """Validated and normalized event used internally."""

    content: str
    source: str
    event_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A single explainable security finding."""

    rule_id: str
    severity: str
    reason: str
    indicator: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "reason": self.reason,
            "indicator": self.indicator,
        }


@dataclass
class RiskResult:
    """Normalized risk assessment."""

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
    """Impact assessment prepared for future expansion."""

    level: str = "UNKNOWN"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "reasons": self.reasons,
        }


@dataclass
class ResponseDecision:
    """Safe response recommendation.

    Actual containment/remediation is intentionally not executed
    by the foundation engine.
    """

    action: str = "NO_ACTION"
    reason: str = "No response action required."

    def to_dict(self) -> dict[str, str]:
        return {
            "action": self.action,
            "reason": self.reason,
        }


@dataclass
class VerificationResult:
    """Verification result for a response decision."""

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
    """Final structured result returned by the security engine."""

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
        """Backward-compatible status alias for legacy consumers."""

        if self.verdict == "SAFE":
            return "SAFE"

        if self.verdict == "SUSPICIOUS":
            if self.risk_score >= 50:
                return "MEDIUM"
            return "LOW"

        if self.verdict == "MALICIOUS":
            return "HIGH"

        return "UNKNOWN"

    def to_dict(self) -> dict[str, Any]:
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


# Backward-compatible alias from the earlier foundation.
AnalysisInput = NormalizedEvent


# Backward-compatible result from TASK-001.
@dataclass
class AnalysisResult:
    """Backward-compatible TASK-001 result."""

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