from security_engine.models import Finding
from typing import Final


SEVERITY_WEIGHTS = {
    "LOW": 20,
    "MEDIUM": 50,
    "HIGH": 80,
    "CRITICAL": 100,
}


CONTEXTUAL_INDICATORS = {
    "suspicious_keyword",
    "urgency",
    "url_shortener",
    "suspicious_tld",
    "reward_scam",
}


RISK_LEVEL_THRESHOLDS: Final[dict[str, int]] = {
    "LOW_MAX": 29,
    "MEDIUM_MAX": 69,
}


def calculate_risk_score(findings: list[Finding]) -> int:
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

    if highest_score >= 100:
        return 100

    if len(primary_findings) >= 2:
        return 100

    return highest_score


def get_risk_level(score: int) -> str:
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")

    if score <= RISK_LEVEL_THRESHOLDS["LOW_MAX"]:
        return "LOW"

    if score <= RISK_LEVEL_THRESHOLDS["MEDIUM_MAX"]:
        return "MEDIUM"

    return "HIGH"
