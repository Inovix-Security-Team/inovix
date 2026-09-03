from security_engine.detectors.base import Detector
from security_engine.models import Finding


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
            urls = analysis.get("urls", [])

            findings.append(
                Finding(
                    rule_id="URL_PRESENT",
                    severity="LOW",
                    reason="URL detected in input.",
                    indicator="url",
                    value=urls[0] if urls else None,
                )
            )

        if analysis.get("contains_ip_url"):
            ip_addresses = analysis.get("ip_addresses", [])

            findings.append(
                Finding(
                    rule_id="IP_BASED_URL",
                    severity="HIGH",
                    reason="URL uses a direct IP address instead of a domain.",
                    indicator="ip_based_url",
                    value=ip_addresses[0] if ip_addresses else None,
                )
            )

        if analysis.get("contains_url_shortener"):
            findings.append(
                Finding(
                    rule_id="URL_SHORTENER",
                    severity="MEDIUM",
                    reason="URL shortening service detected.",
                    indicator="url_shortener",
                )
            )

        if analysis.get("contains_suspicious_tld"):
            findings.append(
                Finding(
                    rule_id="SUSPICIOUS_TLD",
                    severity="MEDIUM",
                    reason="URL contains a suspicious top-level domain.",
                    indicator="suspicious_tld",
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

        if analysis.get("contains_urgency"):
            findings.append(
                Finding(
                    rule_id="URGENCY_LANGUAGE",
                    severity="MEDIUM",
                    reason="Urgent or time-pressure language detected.",
                    indicator="urgency",
                )
            )

        if analysis.get("contains_threat_language"):
            findings.append(
                Finding(
                    rule_id="THREAT_LANGUAGE",
                    severity="HIGH",
                    reason="Threatening or account-suspension language detected.",
                    indicator="threat_language",
                )
            )

        if analysis.get("contains_reward_scam"):
            findings.append(
                Finding(
                    rule_id="REWARD_SCAM",
                    severity="MEDIUM",
                    reason="Potential reward or prize scam language detected.",
                    indicator="reward_scam",
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
