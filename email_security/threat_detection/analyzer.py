from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from email_security.email_forensics.models import EmailForensicResult
from email_security.email_models.email_models import EmailMessageData
from email_security.ioc.models import EmailIOCExtractionResult
from security_engine.models import Finding

from .rules import (
    CREDENTIAL_REQUEST,
    FINANCIAL_REQUEST,
    IMPERSONATION,
    PHISHING_URGENT_LANGUAGE,
    SOCIAL_ENGINEERING,
    contains_rule_pattern,
)


class EmailThreatSignalProvider(Protocol):
    """Interface for deterministic or future NLP/ML signal providers."""

    def detect(
        self,
        email: EmailMessageData,
        forensic_result: EmailForensicResult | None,
        ioc_result: EmailIOCExtractionResult | None,
    ) -> list[Finding]:
        """Return explainable threat findings for an email."""
        ...


@dataclass(frozen=True)
class RuleBasedEmailThreatAnalyzer:
    """Offline, deterministic email threat analyzer."""

    def detect(
        self,
        email: EmailMessageData,
        forensic_result: EmailForensicResult | None = None,
        ioc_result: EmailIOCExtractionResult | None = None,
    ) -> list[Finding]:
        """Analyze an email using deterministic rules and existing evidence."""

        text = _email_text(email)

        findings = _content_findings(text)
        findings.extend(_ioc_findings(ioc_result))
        findings.extend(_forensic_findings(forensic_result))

        return _deduplicate_findings(findings)


class EmailThreatAnalyzer:
    """Orchestrate email threat analysis.

    The current implementation is deterministic and rule-based.
    A future NLP/ML provider can implement EmailThreatSignalProvider
    without changing the email detection interface.
    """

    def __init__(
        self,
        signal_provider: EmailThreatSignalProvider | None = None,
    ) -> None:
        self.signal_provider = (
            signal_provider
            or RuleBasedEmailThreatAnalyzer()
        )

    def analyze(
        self,
        email: EmailMessageData,
        forensic_result: EmailForensicResult | None = None,
        ioc_result: EmailIOCExtractionResult | None = None,
    ) -> list[Finding]:
        """Return threat findings for the supplied parsed email."""

        return self.signal_provider.detect(
            email,
            forensic_result,
            ioc_result,
        )


def _email_text(email: EmailMessageData) -> str:
    """Build searchable text from parsed email content."""

    parts = (
        email.subject or "",
        email.text_body or "",
        email.html_body or "",
    )

    return "\n".join(
        part
        for part in parts
        if part
    )


def _content_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []

    for rule in (
        PHISHING_URGENT_LANGUAGE,
        CREDENTIAL_REQUEST,
        FINANCIAL_REQUEST,
        SOCIAL_ENGINEERING,
        IMPERSONATION,
    ):
        if contains_rule_pattern(text, rule):
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    reason=rule.reason,
                    indicator=rule.indicator,
                )
            )

    return findings


def _ioc_findings(
    ioc_result: EmailIOCExtractionResult | None,
) -> list[Finding]:
    """Use existing IOC extraction as supporting threat evidence."""

    if ioc_result is None:
        return []

    findings: list[Finding] = []

    for ioc in ioc_result.iocs:
        if ioc.ioc_type.value != "URL":
            continue

        suspicious_reason = _suspicious_url_reason(ioc.value)

        if suspicious_reason is None:
            continue

        findings.append(
            Finding(
                rule_id="SUSPICIOUS_URL",
                severity="MEDIUM",
                reason=suspicious_reason,
                indicator="suspicious_url",
                value=ioc.value,
            )
        )

    return findings


def _suspicious_url_reason(url: str) -> str | None:
    """Identify locally observable suspicious URL characteristics."""

    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    hostname = (parsed.hostname or "").casefold()

    if not hostname:
        return None

    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
    }

    suspicious_tlds = (
        ".tk",
        ".top",
        ".xyz",
        ".click",
        ".gq",
        ".ml",
    )

    if hostname in shorteners:
        return (
            "The email contains a URL-shortening service, "
            "which can obscure the destination."
        )

    if hostname.endswith(suspicious_tlds):
        return (
            "The email contains a URL using a locally configured "
            "suspicious top-level domain."
        )

    if _is_ip_hostname(hostname):
        return (
            "The email contains a URL addressed directly to an IP "
            "address instead of a domain name."
        )

    return None


def _is_ip_hostname(hostname: str) -> bool:
    """Return whether a hostname is an IPv4 or IPv6 literal."""

    import ipaddress

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _forensic_findings(
    forensic_result: EmailForensicResult | None,
) -> list[Finding]:
    """Translate existing forensic mismatches into security findings."""

    if forensic_result is None:
        return []

    findings: list[Finding] = []
    identity = forensic_result.identity_analysis

    if identity.reply_to_domain_match is False:
        findings.append(
            Finding(
                rule_id="REPLY_TO_MISMATCH",
                severity="HIGH",
                reason=(
                    "The forensic analysis identified a Reply-To "
                    "domain mismatch with the sender."
                ),
                indicator="reply_to_mismatch",
                value=", ".join(identity.reply_to_addresses) or None,
            )
        )

    if identity.return_path_domain_match is False:
        findings.append(
            Finding(
                rule_id="RETURN_PATH_MISMATCH",
                severity="HIGH",
                reason=(
                    "The forensic analysis identified a Return-Path "
                    "domain mismatch with the sender."
                ),
                indicator="return_path_mismatch",
                value=identity.return_path or None,
            )
        )

    return findings


def _deduplicate_findings(
    findings: list[Finding],
) -> list[Finding]:
    """Remove duplicate findings while preserving detection order."""

    seen: set[tuple[str, str | None]] = set()
    result: list[Finding] = []

    for finding in findings:
        key = (
            finding.rule_id,
            finding.value,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(finding)

    return result
