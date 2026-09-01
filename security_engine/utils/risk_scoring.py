from security_engine.models import Finding

SEVERITY_WEIGHTS = {
    "LOW": 20,
    "MEDIUM": 50,
    "HIGH": 80,
    "CRITICAL": 100,
}


# Findings that describe context rather than independently
# determining the primary risk level.
CONTEXTUAL_INDICATORS = {
    "suspicious_keyword",
    "urgency",
    "url_shortener",
    "suspicious_tld",
    "reward_scam",
}


def calculate_risk_score(findings: list[Finding]) -> int:
    """Calculate a normalized 0-100 risk score.

    Primary findings determine the base risk. Contextual findings
    are retained for explanation but do not independently increase
    the score. Multiple independent primary findings can escalate
    the final score to 100.
    """

    if not findings:
        return 0

    primary_findings = [
        finding
        for finding in findings
        if finding.indicator not in CONTEXTUAL_INDICATORS
    ]

    if not primary_findings:
        return max(
            SEVERITY_WEIGHTS.get(
                finding.severity.upper(),
                0,
            )
            for finding in findings
        )

    highest_score = max(
        SEVERITY_WEIGHTS.get(
            finding.severity.upper(),
            0,
        )
        for finding in primary_findings
    )

    # Critical findings are already maximum risk.
    if highest_score >= 100:
        return 100

    # Multiple independent primary findings indicate
    # correlated malicious activity.
    if len(primary_findings) >= 2:
        return 100

    return highest_score