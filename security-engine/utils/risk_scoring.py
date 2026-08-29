from models import Finding


SEVERITY_WEIGHTS = {
    "LOW": 20,
    "MEDIUM": 50,
    "HIGH": 80,
    "CRITICAL": 100,
}


def calculate_risk_score(findings: list[Finding]) -> int:
    """Calculate a normalized 0-100 risk score."""

    if not findings:
        return 0

    score = sum(
        SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)
        for finding in findings
    )

    return min(score, 100)