import pytest

from security_engine.models import Finding
from security_engine.utils.risk_scoring import calculate_risk_score


def make_finding(severity: str) -> Finding:
    return Finding(
        rule_id=f"TEST_{severity}",
        severity=severity,
        reason=f"{severity} test finding.",
        indicator=f"{severity.lower()}_indicator",
    )


@pytest.mark.parametrize(
    "severity, expected_score",
    [
        ("LOW", 20),
        ("MEDIUM", 50),
        ("HIGH", 80),
        ("CRITICAL", 100),
    ],
)
def test_single_finding_score(severity, expected_score):
    finding = make_finding(severity)

    assert calculate_risk_score([finding]) == expected_score


def test_empty_findings_score_zero():
    assert calculate_risk_score([]) == 0


def test_multiple_findings_are_combined():
    findings = [
        make_finding("LOW"),
        make_finding("MEDIUM"),
    ]

    assert calculate_risk_score(findings) == 70


def test_multiple_high_findings_are_capped_at_100():
    findings = [
        make_finding("HIGH"),
        make_finding("HIGH"),
    ]

    assert calculate_risk_score(findings) == 100


def test_critical_finding_caps_score_at_100():
    findings = [
        make_finding("CRITICAL"),
        make_finding("HIGH"),
    ]

    assert calculate_risk_score(findings) == 100


def test_unknown_severity_contributes_zero():
    finding = make_finding("UNKNOWN")

    assert calculate_risk_score([finding]) == 0
