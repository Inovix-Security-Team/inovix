import pytest

from engine import SecurityEngine
from exceptions import InvalidInputError


@pytest.fixture
def engine():
    return SecurityEngine()


def test_security_empty_input(engine):
    with pytest.raises(InvalidInputError):
        engine.analyze("")


def test_security_safe_sample(engine):
    result = engine.analyze(
        "User login successful.",
        source="192.168.1.50",
        event_type="user_login",
    )

    assert result.risk_score == 0
    assert result.verdict == "SAFE"
    assert result.findings == []


def test_security_credential_request(engine):
    result = engine.analyze(
        "Please send your password and OTP.",
        source="10.0.0.105",
        event_type="phishing_attempt",
    )

    assert result.risk_score == 80
    assert result.verdict == "MALICIOUS"

    assert result.findings[0].rule_id == "CREDENTIAL_REQUEST"


def test_security_financial_request(engine):
    result = engine.analyze(
        "Please complete the bank transfer immediately.",
        source="10.0.0.106",
        event_type="bec_attempt",
    )

    assert result.risk_score == 80
    assert result.verdict == "MALICIOUS"


def test_security_impersonation(engine):
    result = engine.analyze(
        "I am from your bank. Please verify your account.",
        source="10.0.0.107",
        event_type="impersonation",
    )

    assert result.risk_score >= 100
    assert result.verdict == "MALICIOUS"


def test_security_multiple_findings(engine):
    result = engine.analyze(
        "Urgent action required. Send your password "
        "and bank transfer details to https://example.com.",
        source="10.0.0.109",
        event_type="phishing_attempt",
    )

    assert len(result.findings) >= 3
    assert len(result.indicators) >= 3
    assert result.risk_score == 100
    assert result.verdict == "MALICIOUS"
