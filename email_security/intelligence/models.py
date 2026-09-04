from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EmailEvidence:
    """
    Evidence preserved by the unified email intelligence layer.
    """

    evidence_id: str
    source: str
    category: str
    description: str
    value: Optional[str] = None
    severity: Optional[str] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "category": self.category,
            "description": self.description,
            "value": self.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
        }


@dataclass
class EmailCorrelation:
    """
    Represents a relationship between multiple independent signals.
    """

    correlation_id: str
    rule_id: str
    title: str
    description: str
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 1.0
    severity: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "severity": self.severity,
            "metadata": dict(self.metadata),
        }


@dataclass
class EmailProvenance:
    """
    Describes which processing stages contributed to the unified result.
    """

    stages: List[str] = field(default_factory=list)
    parser_used: bool = False
    forensics_used: bool = False
    ioc_extraction_used: bool = False
    threat_detection_used: bool = False
    correlation_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stages": list(self.stages),
            "parser_used": self.parser_used,
            "forensics_used": self.forensics_used,
            "ioc_extraction_used": self.ioc_extraction_used,
            "threat_detection_used": self.threat_detection_used,
            "correlation_used": self.correlation_used,
        }


@dataclass
class EmailIntelligenceResult:
    """
    Unified output produced by EMAIL-INT-007.
    """

    verdict: str
    risk_score: int
    confidence: float

    reasons: List[str] = field(default_factory=list)
    findings: List[Any] = field(default_factory=list)
    evidence: List[EmailEvidence] = field(default_factory=list)
    correlations: List[EmailCorrelation] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)

    provenance: EmailProvenance = field(
        default_factory=EmailProvenance
    )

    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "findings": [
                finding.to_dict()
                if hasattr(finding, "to_dict")
                else finding
                for finding in self.findings
            ],
            "evidence": [
                item.to_dict()
                for item in self.evidence
            ],
            "correlations": [
                item.to_dict()
                for item in self.correlations
            ],
            "indicators": list(self.indicators),
            "provenance": self.provenance.to_dict(),
            "metadata": dict(self.metadata),
        }
