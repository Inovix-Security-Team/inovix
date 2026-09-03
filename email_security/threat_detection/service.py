from __future__ import annotations

from dataclasses import dataclass

from email_security.email_forensics.email_forensics import (
    EmailForensicsAnalyzer,
)
from email_security.email_models.email_models import EmailMessageData
from email_security.email_parser.email_parser import EmailParser
from email_security.ioc.extractor import EmailIOCExtractor
from email_security.ioc.models import EmailIOCExtractionResult
from security_engine.models import Finding, RiskResult, SecurityResult
from security_engine.utils.risk_scoring import calculate_risk_score
from security_engine.utils.verdict import generate_verdict

from .analyzer import EmailThreatAnalyzer


@dataclass
class EmailThreatDetectionService:
    """End-to-end offline email threat detection service.

    The service reuses the existing email parser, forensic analyzer,
    IOC extractor, threat analyzer, risk scorer, and verdict generator.
    No independent scoring or external intelligence is introduced.
    """

    parser: EmailParser | None = None
    forensics_analyzer: EmailForensicsAnalyzer | None = None
    ioc_extractor: EmailIOCExtractor | None = None
    threat_analyzer: EmailThreatAnalyzer | None = None

    def __post_init__(self) -> None:
        if self.parser is None:
            self.parser = EmailParser()

        if self.forensics_analyzer is None:
            self.forensics_analyzer = EmailForensicsAnalyzer()

        if self.ioc_extractor is None:
            self.ioc_extractor = EmailIOCExtractor()

        if self.threat_analyzer is None:
            self.threat_analyzer = EmailThreatAnalyzer()

    def analyze(
        self,
        email: EmailMessageData,
        forensic_result=None,
        ioc_result: EmailIOCExtractionResult | None = None,
    ) -> SecurityResult:
        """Analyze an already-parsed email and return SecurityResult."""

        if forensic_result is None:
            forensic_result = self.forensics_analyzer.analyze(email)

        if ioc_result is None:
            ioc_result = self.ioc_extractor.extract(
                email,
                forensic_result=forensic_result,
            )

        findings = self.threat_analyzer.analyze(
            email,
            forensic_result=forensic_result,
            ioc_result=ioc_result,
        )

        return self._build_security_result(findings)

    def analyze_raw(self, raw_email: str | bytes) -> SecurityResult:
        """Parse and analyze raw RFC-compliant email data."""

        email = self.parser.parse_raw(raw_email)
        return self.analyze(email)

    def _build_security_result(
        self,
        findings: list[Finding],
    ) -> SecurityResult:
        """Build the shared SecurityResult using existing scoring logic."""

        risk_score = calculate_risk_score(findings)
        verdict = generate_verdict(risk_score)

        reasons = [
            finding.reason
            for finding in findings
        ]

        indicators = [
            finding.indicator
            for finding in findings
        ]

        risk_level = verdict

        if verdict == "SAFE":
            risk_level = "LOW"
        elif verdict == "SUSPICIOUS":
            risk_level = "MEDIUM"
        elif verdict == "MALICIOUS":
            risk_level = "HIGH"

        risk = RiskResult(
            score=risk_score,
            level=risk_level,
            reasons=reasons.copy(),
        )

        return SecurityResult(
            verdict=verdict,
            risk_score=risk_score,
            reasons=reasons,
            indicators=indicators,
            findings=findings,
            risk=risk,
        )
