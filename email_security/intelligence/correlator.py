from __future__ import annotations

from typing import Iterable

from security_engine.models import Finding

from email_security.email_forensics.models import EmailForensicResult
from email_security.ioc.models import (
    EmailIOCExtractionResult,
    ExtractionConfidence,
)

from .models import (
    EmailCorrelation,
    EmailEvidence,
)


class EmailCorrelationEngine:
    """Correlates independent email security signals into higher-level findings."""

    def correlate(
        self,
        findings: Iterable[Finding],
        forensic_result: EmailForensicResult | None,
        ioc_result: EmailIOCExtractionResult | None,
    ) -> tuple[tuple[EmailEvidence, ...], tuple[EmailCorrelation, ...]]:
        findings = tuple(findings)

        evidence = self._build_evidence(
            findings=findings,
            forensic_result=forensic_result,
            ioc_result=ioc_result,
        )

        correlations: list[EmailCorrelation] = []

        identity_auth = self._identity_auth_correlation(
            findings=findings,
            forensic_result=forensic_result,
            evidence=evidence,
        )
        if identity_auth is not None:
            correlations.append(identity_auth)

        phishing = self._phishing_correlation(findings, evidence)
        if phishing is not None:
            correlations.append(phishing)

        financial = self._financial_correlation(
            findings=findings,
            forensic_result=forensic_result,
            evidence=evidence,
        )
        if financial is not None:
            correlations.append(financial)

        ioc_correlation = self._ioc_correlation(
            findings=findings,
            ioc_result=ioc_result,
            evidence=evidence,
        )
        if ioc_correlation is not None:
            correlations.append(ioc_correlation)

        return evidence, tuple(correlations)

    def _build_evidence(
        self,
        findings: tuple[Finding, ...],
        forensic_result: EmailForensicResult | None,
        ioc_result: EmailIOCExtractionResult | None,
    ) -> tuple[EmailEvidence, ...]:
        evidence: list[EmailEvidence] = []
        counter = 1

        for finding in findings:
            evidence.append(
                EmailEvidence(
                    evidence_id=f"E{counter:04d}",
                    source="threat_detection",
                    category=finding.rule_id,
                    description=finding.reason,
                    value=finding.indicator,
                    severity=finding.severity,
                    confidence=1.0,
                    metadata={
                        "finding_value": finding.value,
                    },
                )
            )
            counter += 1

        if forensic_result is not None:
            for forensic in forensic_result.evidence:
                evidence.append(
                    EmailEvidence(
                        evidence_id=f"E{counter:04d}",
                        source="forensics",
                        category=self._forensic_category(forensic),
                        description=forensic.reason,
                        value=forensic.raw_value,
                        confidence=1.0,
                        metadata={
                            "parsed_value": forensic.parsed_value,
                            "source": forensic.source,
                        },
                    )
                )
                counter += 1

        if ioc_result is not None:
            for ioc in ioc_result.iocs:
                evidence.append(
                    EmailEvidence(
                        evidence_id=f"E{counter:04d}",
                        source="ioc_extraction",
                        category=ioc.ioc_type.value,
                        description=f"Extracted {ioc.ioc_type.value} IOC",
                        value=ioc.value,
                        confidence=self._ioc_confidence(ioc.confidence),
                        metadata={
                            "occurrence_count": len(ioc.occurrences),
                            "extraction_confidence": ioc.confidence.value,
                            "sources": [source.value for source in ioc.sources],
                            "locations": list(ioc.locations),
                        },
                    )
                )
                counter += 1

        return tuple(evidence)

    @staticmethod
    def _forensic_category(forensic_evidence: object) -> str:
        """
        Preserve recognizable forensic signal categories when available.

        The forensic analyzer records authentication anomalies such as
        SPF_FAILURE, DKIM_FAILURE and DMARC_FAILURE. Keeping those categories
        allows the correlation layer to combine them with identity anomalies.
        """
        source = getattr(forensic_evidence, "source", "")
        raw_value = getattr(forensic_evidence, "raw_value", "")
        reason = getattr(forensic_evidence, "reason", "")

        text = " ".join(
            str(value)
            for value in (source, raw_value, reason)
            if value
        ).upper()

        for category in (
            "SPF_FAILURE",
            "DKIM_FAILURE",
            "DMARC_FAILURE",
            "AUTHENTICATION_EVIDENCE_MISSING",
            "FROM_REPLY_TO_MISMATCH",
            "FROM_RETURN_PATH_MISMATCH",
            "MALFORMED_RECEIVED_HEADER",
            "PRIVATE_OR_RESERVED_RECEIVED_IP",
        ):
            if category in text:
                return category

        return "FORENSIC_EVIDENCE"

    @staticmethod
    def _ioc_confidence(confidence: ExtractionConfidence) -> float:
        if confidence == ExtractionConfidence.HIGH:
            return 1.0
        if confidence == ExtractionConfidence.MEDIUM:
            return 0.75
        if confidence == ExtractionConfidence.LOW:
            return 0.5
        return 0.5

    def _identity_auth_correlation(
        self,
        findings: tuple[Finding, ...],
        forensic_result: EmailForensicResult | None,
        evidence: tuple[EmailEvidence, ...],
    ) -> EmailCorrelation | None:
        if forensic_result is None:
            return None

        identity = forensic_result.identity_analysis

        identity_mismatch = (
            self._has_finding(
                findings,
                {
                    "FROM_REPLY_TO_MISMATCH",
                    "REPLY_TO_MISMATCH",
                },
            )
            or self._has_finding(
                findings,
                {
                    "FROM_RETURN_PATH_MISMATCH",
                    "RETURN_PATH_MISMATCH",
                },
            )
            or (
                identity is not None
                and (
                    identity.reply_to_domain_match is False
                    or identity.return_path_domain_match is False
                )
            )
        )

        authentication_failure = (
            self._has_finding(
                findings,
                {
                    "SPF_FAILURE",
                    "DKIM_FAILURE",
                    "DMARC_FAILURE",
                },
            )
            or self._has_forensic_category(
                forensic_result,
                {
                    "SPF_FAILURE",
                    "DKIM_FAILURE",
                    "DMARC_FAILURE",
                },
            )
        )

        if not (identity_mismatch and authentication_failure):
            return None

        evidence_ids = self._matching_evidence_ids(
            evidence,
            categories={
                "FROM_REPLY_TO_MISMATCH",
                "FROM_RETURN_PATH_MISMATCH",
                "REPLY_TO_MISMATCH",
                "RETURN_PATH_MISMATCH",
                "SPF_FAILURE",
                "DKIM_FAILURE",
                "DMARC_FAILURE",
            },
        )

        return EmailCorrelation(
            correlation_id="C0001",
            rule_id="IDENTITY_AUTH_ANOMALY",
            title="Identity and authentication anomaly",
            description=(
                "Sender identity differs from Reply-To or Return-Path while "
                "email authentication contains one or more failures."
            ),
            evidence_ids=evidence_ids,
            confidence=0.95,
            severity="HIGH",
            metadata={
                "identity_mismatch": True,
                "authentication_failure": True,
            },
        )

    def _phishing_correlation(
        self,
        findings: tuple[Finding, ...],
        evidence: tuple[EmailEvidence, ...],
    ) -> EmailCorrelation | None:
        urgent = self._has_finding(
            findings,
            {
                "PHISHING_URGENT_LANGUAGE",
                "URGENT_LANGUAGE",
            },
        )

        credential = self._has_finding(
            findings,
            {
                "CREDENTIAL_REQUEST",
            },
        )

        suspicious_url = self._has_finding(
            findings,
            {
                "SUSPICIOUS_URL",
            },
        )

        if not (urgent and credential and suspicious_url):
            return None

        return EmailCorrelation(
            correlation_id="C0002",
            rule_id="PHISHING_CAMPAIGN_PATTERN",
            title="Phishing campaign pattern",
            description=(
                "Urgent language, credential solicitation and a suspicious "
                "URL occur together."
            ),
            evidence_ids=self._matching_evidence_ids(
                evidence,
                categories={
                    "PHISHING_URGENT_LANGUAGE",
                    "URGENT_LANGUAGE",
                    "CREDENTIAL_REQUEST",
                    "SUSPICIOUS_URL",
                },
            ),
            confidence=0.95,
            severity="HIGH",
        )

    def _financial_correlation(
        self,
        findings: tuple[Finding, ...],
        forensic_result: EmailForensicResult | None,
        evidence: tuple[EmailEvidence, ...],
    ) -> EmailCorrelation | None:
        financial = self._has_finding(
            findings,
            {
                "FINANCIAL_REQUEST",
            },
        )

        urgent = self._has_finding(
            findings,
            {
                "PHISHING_URGENT_LANGUAGE",
                "URGENT_LANGUAGE",
            },
        )

        mismatch = self._has_finding(
            findings,
            {
                "REPLY_TO_MISMATCH",
                "RETURN_PATH_MISMATCH",
                "FROM_REPLY_TO_MISMATCH",
                "FROM_RETURN_PATH_MISMATCH",
            },
        )

        if forensic_result is not None:
            identity = forensic_result.identity_analysis
            if identity is not None:
                mismatch = mismatch or (
                    identity.reply_to_domain_match is False
                    or identity.return_path_domain_match is False
                )

        if not (financial and urgent and mismatch):
            return None

        return EmailCorrelation(
            correlation_id="C0003",
            rule_id="FINANCIAL_SOCIAL_ENGINEERING_PATTERN",
            title="Financial social-engineering pattern",
            description=(
                "Financial request and urgency are combined with sender "
                "identity inconsistency."
            ),
            evidence_ids=self._matching_evidence_ids(
                evidence,
                categories={
                    "FINANCIAL_REQUEST",
                    "PHISHING_URGENT_LANGUAGE",
                    "URGENT_LANGUAGE",
                    "REPLY_TO_MISMATCH",
                    "RETURN_PATH_MISMATCH",
                    "FROM_REPLY_TO_MISMATCH",
                    "FROM_RETURN_PATH_MISMATCH",
                },
            ),
            confidence=0.95,
            severity="HIGH",
        )

    def _ioc_correlation(
        self,
        findings: tuple[Finding, ...],
        ioc_result: EmailIOCExtractionResult | None,
        evidence: tuple[EmailEvidence, ...],
    ) -> EmailCorrelation | None:
        if ioc_result is None or not ioc_result.iocs:
            return None

        suspicious_url = self._has_finding(
            findings,
            {
                "SUSPICIOUS_URL",
            },
        )

        if not suspicious_url:
            return None

        return EmailCorrelation(
            correlation_id="C0004",
            rule_id="SUSPICIOUS_URL_IOC",
            title="Suspicious URL with extracted IOC",
            description=(
                "Threat detection identified a suspicious URL and the IOC "
                "extraction layer independently preserved the URL as evidence."
            ),
            evidence_ids=self._matching_evidence_ids(
                evidence,
                categories={
                    "SUSPICIOUS_URL",
                    "URL",
                },
            ),
            confidence=0.9,
            severity="HIGH",
        )

    @staticmethod
    def _has_finding(
        findings: tuple[Finding, ...],
        rule_ids: set[str],
    ) -> bool:
        return any(finding.rule_id in rule_ids for finding in findings)

    @staticmethod
    def _has_forensic_category(
        forensic_result: EmailForensicResult,
        categories: set[str],
    ) -> bool:
        for anomaly in forensic_result.anomalies:
            anomaly_text = str(anomaly).upper()

            if any(category in anomaly_text for category in categories):
                return True

        return False

    @staticmethod
    def _matching_evidence_ids(
        evidence: tuple[EmailEvidence, ...],
        categories: set[str],
    ) -> tuple[str, ...]:
        return tuple(
            item.evidence_id
            for item in evidence
            if item.category in categories
        )
