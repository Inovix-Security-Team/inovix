from __future__ import annotations

from typing import Optional
from hashlib import sha256
from datetime import datetime, timezone

from database.models import (
    EventRecord,
    FindingRecord,
    RiskAssessmentRecord,
)
from database.service import DatabaseService

from email_security.email_forensics.email_forensics import (
    EmailForensicsAnalyzer,
)
from email_security.email_forensics.models import EmailForensicResult
from email_security.email_models.email_models import EmailMessageData
from email_security.email_parser.email_parser import EmailParser
from email_security.ioc.extractor import EmailIOCExtractor
from email_security.ioc.models import EmailIOCExtractionResult
from email_security.threat_detection.service import (
    EmailThreatDetectionService,
)

from .correlator import EmailCorrelationEngine
from .models import (
    EmailIntelligenceResult,
    EmailProvenance,
)


class EmailIntelligenceService:
    """
    Unified orchestration service for EMAIL-INT-007.

    Pipeline:

        raw .eml
            -> parser
            -> forensics
            -> IOC extraction
            -> threat detection
            -> correlation
            -> unified result

    Existing threat detection, risk scoring, and verdict generation
    remain responsible for the base SecurityResult.
    """

    def __init__(
        self,
        parser: Optional[EmailParser] = None,
        forensics: Optional[EmailForensicsAnalyzer] = None,
        ioc_extractor: Optional[EmailIOCExtractor] = None,
        threat_detection: Optional[
            EmailThreatDetectionService
        ] = None,
        correlation: Optional[EmailCorrelationEngine] = None,
    ) -> None:
        self.parser = parser or EmailParser()

        self.forensics = (
            forensics
            or EmailForensicsAnalyzer()
        )

        self.ioc_extractor = (
            ioc_extractor
            or EmailIOCExtractor()
        )

        self.threat_detection = (
            threat_detection
            or EmailThreatDetectionService(
                parser=self.parser,
                forensics_analyzer=self.forensics,
                ioc_extractor=self.ioc_extractor,
            )
        )

        self.correlation = (
            correlation
            or EmailCorrelationEngine()
        )

    def analyze(
        self,
        email: EmailMessageData,
        forensic_result: Optional[
            EmailForensicResult
        ] = None,
        ioc_result: Optional[
            EmailIOCExtractionResult
        ] = None,
    ) -> EmailIntelligenceResult:
        """
        Analyze an already-parsed email.
        """

        supplied_forensic = forensic_result is not None
        supplied_ioc = ioc_result is not None

        if forensic_result is None:
            forensic_result = self.forensics.analyze(email)

        if ioc_result is None:
            ioc_result = self.ioc_extractor.extract(
                email,
                forensic_result=forensic_result,
            )

        security_result = self.threat_detection.analyze(
            email,
            forensic_result=forensic_result,
            ioc_result=ioc_result,
        )

        findings = list(security_result.findings)

        evidence, correlations = (
            self.correlation.correlate(
                findings=findings,
                forensic_result=forensic_result,
                ioc_result=ioc_result,
            )
        )

        reasons = list(security_result.reasons)

        for correlation in correlations:
            if correlation.description not in reasons:
                reasons.append(
                    correlation.description
                )

        indicators = list(
            security_result.indicators
        )

        for ioc in ioc_result.iocs:
            if ioc.value not in indicators:
                indicators.append(ioc.value)

        confidence = self._calculate_confidence(
            evidence=evidence,
            correlations=list(correlations),
        )

        provenance = EmailProvenance(
            stages=[
                "parser",
                "forensics",
                "ioc_extraction",
                "threat_detection",
                "correlation",
            ],
            parser_used=False,
            forensics_used=True,
            ioc_extraction_used=True,
            threat_detection_used=True,
            correlation_used=bool(
                evidence or correlations
            ),
        )

        if supplied_forensic:
            provenance.stages.append(
                "precomputed_forensics"
            )

        if supplied_ioc:
            provenance.stages.append(
                "precomputed_ioc"
            )

        return EmailIntelligenceResult(
            verdict=security_result.verdict,
            risk_score=security_result.risk_score,
            confidence=confidence,
            reasons=reasons,
            findings=findings,
            evidence=evidence,
            correlations=list(correlations),
            indicators=indicators,
            provenance=provenance,
        )

    def persist(
        self,
        result: EmailIntelligenceResult,
        database: DatabaseService,
        *,
        event_id: str,
        email: Optional[EmailMessageData] = None,
        content_hash: Optional[str] = None,
    ) -> dict:
        """
        Persist a unified email intelligence result through the
        existing DatabaseService transaction boundary.

        EMAIL-INT-007-specific evidence, correlations, confidence,
        provenance, and indicators are preserved in the existing
        events.metadata JSON field. Findings and risk continue to use
        the existing repository contracts.
        """

        if not event_id or not event_id.strip():
            raise ValueError("event_id must not be empty")

        if email is not None and content_hash is None:
            canonical_content = "|".join(
                [
                    email.sender or "",
                    ",".join(email.recipients or []),
                    email.subject or "",
                    email.text_body or "",
                    email.html_body or "",
                    email.message_id or "",
                ]
            )

            content_hash = sha256(
                canonical_content.encode("utf-8")
            ).hexdigest()

        timestamp = (
            email.date
            if email is not None and email.date
            else datetime.now(timezone.utc).isoformat()
        )

        source = (
            email.sender
            if email is not None and email.sender
            else "email_intelligence"
        )

        metadata = {
            "intelligence_version": "EMAIL-INT-007",
            "confidence": result.confidence,
            "indicators": list(result.indicators),
            "reasons": list(result.reasons),
            "evidence": [
                item.to_dict()
                for item in result.evidence
            ],
            "correlations": [
                item.to_dict()
                for item in result.correlations
            ],
            "provenance": result.provenance.to_dict(),
            "metadata": dict(result.metadata),
        }

        event = EventRecord(
            id=event_id,
            timestamp=timestamp,
            event_type="EMAIL_INTELLIGENCE",
            source=source,
            content_hash=content_hash,
            metadata=metadata,
        )

        findings = [
            FindingRecord(
                event_id=event_id,
                rule_id=finding.rule_id,
                severity=finding.severity,
                reason=finding.reason,
                indicator=finding.indicator or "",
            )
            for finding in result.findings
        ]

        risk = RiskAssessmentRecord(
            event_id=event_id,
            score=result.risk_score,
            risk_level=self._risk_level(result.risk_score),
            verdict=result.verdict,
        )

        return database.save_analysis(
            event=event,
            findings=findings,
            risk=risk,
        )

    @staticmethod
    def _risk_level(score: int) -> str:
        if score <= 29:
            return "LOW"
        if score <= 69:
            return "MEDIUM"
        return "HIGH"
    def analyze_raw(
        self,
        raw_email: str | bytes,
    ) -> EmailIntelligenceResult:
        """
        Parse and analyze raw RFC-compliant email data.
        """

        if isinstance(raw_email, str):
            if not raw_email.strip():
                raise ValueError(
                    "raw_email must not be empty"
                )

        elif isinstance(raw_email, bytes):
            if not raw_email.strip():
                raise ValueError(
                    "raw_email must not be empty"
                )

        else:
            raise TypeError(
                "raw_email must be str or bytes"
            )

        email = self.parser.parse_raw(
            raw_email
        )

        result = self.analyze(email)

        result.provenance.parser_used = True

        return result

    @staticmethod
    def _calculate_confidence(
        evidence,
        correlations,
    ) -> float:
        """
        Calculate confidence independently from risk.

        Risk answers how dangerous the email appears.
        Confidence answers how strongly the available evidence
        supports the analysis.
        """

        if not evidence:
            return 0.0

        evidence_confidences = [
            max(
                0.0,
                min(
                    1.0,
                    float(item.confidence),
                ),
            )
            for item in evidence
        ]

        evidence_confidence = (
            sum(evidence_confidences)
            / len(evidence_confidences)
        )

        if not correlations:
            return round(
                evidence_confidence,
                3,
            )

        correlation_confidences = [
            max(
                0.0,
                min(
                    1.0,
                    float(item.confidence),
                ),
            )
            for item in correlations
        ]

        correlation_confidence = (
            sum(correlation_confidences)
            / len(correlation_confidences)
        )

        return round(
            (evidence_confidence * 0.6)
            + (correlation_confidence * 0.4),
            3,
        )
