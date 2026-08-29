from detectors.base import Detector
from models import Finding


class RuleBasedDetector(Detector):
    """Rule-based security detector."""

    def detect(self, analysis: dict) -> list[Finding]:
        """Generate explainable security findings."""

        findings: list[Finding] = []

        if analysis.get("contains_suspicious_keyword"):
            findings.append(
                Finding(
                    rule_id="SUSPICIOUS_LANGUAGE",
                    severity="MEDIUM",
                    reason="Suspicious social-engineering language detected.",
                    indicator="suspicious_keyword",
                )
            )

        if analysis.get("contains_url"):
            findings.append(
                Finding(
                    rule_id="URL_PRESENT",
                    severity="LOW",
                    reason="URL detected in input.",
                    indicator="url",
                )
            )

        if analysis.get("contains_credential_request"):
            findings.append(
                Finding(
                    rule_id="CREDENTIAL_REQUEST",
                    severity="HIGH",
                    reason=(
                        "Request for sensitive credentials or "
                        "authentication information detected."
                    ),
                    indicator="credential_request",
                )
            )

        if analysis.get("contains_financial_request"):
            findings.append(
                Finding(
                    rule_id="FINANCIAL_REQUEST",
                    severity="HIGH",
                    reason=(
                        "Request involving money transfer or "
                        "financial information detected."
                    ),
                    indicator="financial_request",
                )
            )

        if analysis.get("contains_impersonation"):
            findings.append(
                Finding(
                    rule_id="IMPERSONATION_LANGUAGE",
                    severity="CRITICAL",
                    reason=(
                        "Possible impersonation of a trusted "
                        "organization detected."
                    ),
                    indicator="impersonation",
                )
            )

        return findings