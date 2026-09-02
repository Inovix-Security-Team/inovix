import pytest

from security_engine.engine import SecurityEngine
from security_engine.exceptions import InvalidInputError

from security_engine.utils.normalization import normalize_input
from utils.risk_scoring import calculate_risk_score
from utils.verdict import generate_verdict


@pytest.fixture
def engine() -> SecurityEngine:
    return SecurityEngine()

from models import (
    ImpactResult,
    NormalizedEvent,
    ResponseDecision,
    RiskResult,
    SecurityEvent,
    VerificationResult,
)


def test_security_event_defaults() -> None:
    event = SecurityEvent(content="Hello Inovix")

    assert event.content == "Hello Inovix"
    assert event.source == "unknown"
    assert event.event_type == "text"
    assert event.metadata == {}


def test_security_event_metadata() -> None:
    event = SecurityEvent(
        content="Test event",
        source="live-agent",
        event_type="message",
        metadata={"user_id": "test", "channel": "chat"},
    )

    assert event.source == "live-agent"
    assert event.event_type == "message"
    assert event.metadata["channel"] == "chat"


def test_normalized_event_structure() -> None:
    event = NormalizedEvent(
        content="Hello Inovix",
        source="local-test",
        event_type="text",
    )

    assert event.content == "Hello Inovix"
    assert event.source == "local-test"
    assert event.event_type == "text"
    assert event.metadata == {}


def test_finding_to_dict() -> None:
    finding = Finding(
        rule_id="TEST_RULE",
        severity="HIGH",
        reason="Test security finding.",
        indicator="test_indicator",
    )

    result = finding.to_dict()

    assert result["rule_id"] == "TEST_RULE"
    assert result["severity"] == "HIGH"
    assert result["reason"] == "Test security finding."
    assert result["indicator"] == "test_indicator"


def test_risk_result_to_dict() -> None:
    result = RiskResult(
        score=70,
        level="SUSPICIOUS",
        reasons=["Suspicious activity detected."],
    )

    formatted = result.to_dict()

    assert formatted["score"] == 70
    assert formatted["level"] == "SUSPICIOUS"
    assert formatted["reasons"] == [
        "Suspicious activity detected."
    ]


def test_impact_result_defaults() -> None:
    result = ImpactResult()

    assert result.level == "UNKNOWN"
    assert result.reasons == []


def test_response_decision_defaults() -> None:
    result = ResponseDecision()

    assert result.action == "NO_ACTION"
    assert result.reason == "No response action required."


def test_verification_result_defaults() -> None:
    result = VerificationResult()

    assert result.verified is True
    assert result.status == "NOT_REQUIRED"
    assert result.details == "No response action was executed."


def test_safe_engine_result_contains_foundation_components(
    engine: SecurityEngine,
) -> None:
    result = engine.analyze("Hello Inovix")

    assert result.verdict == "SAFE"
    assert result.risk_score == 0

    assert result.impact is not None
    assert result.impact.level == "LOW"

    assert result.response is not None
    assert result.response.action == "NO_ACTION"

    assert result.verification is not None
    assert result.verification.verified is True


def test_suspicious_engine_result_contains_foundation_components(
    engine: SecurityEngine,
) -> None:
    result = engine.analyze(
        "Urgent action required. Please verify account immediately."
    )

    assert result.verdict == "SUSPICIOUS"
    assert result.risk_score == 50

    assert result.impact is not None
    assert result.impact.level == "MEDIUM"

    assert result.response is not None
    assert result.response.action == "MONITOR"

    assert result.verification is not None
    assert result.verification.status == "NOT_EXECUTED"


def test_security_result_to_dict_contains_foundation_layers(
    engine: SecurityEngine,
) -> None:
    result = engine.analyze(
        "Urgent action required. Please verify account immediately."
    )

    formatted = result.to_dict()

    assert formatted["verdict"] == "SUSPICIOUS"
    assert formatted["risk_score"] == 50
    assert "findings" in formatted
    assert "impact" in formatted
    assert "response" in formatted
    assert "verification" in formatted

    assert formatted["impact"]["level"] == "MEDIUM"
    assert formatted["response"]["action"] == "MONITOR"
    assert formatted["verification"]["verified"] is True


def test_event_type_is_preserved(engine: SecurityEngine) -> None:
    result = engine.analyze(
        "Hello Inovix",
        source="live-agent",
        event_type="chat",
        metadata={"session": "test"},
    )

    assert result.verdict == "SAFE"
def test_credential_request_detection(engine: SecurityEngine) -> None:
    result = engine.analyze(
        "Please send me your password and OTP."
    )

    assert result.verdict == "MALICIOUS"
    assert result.risk_score == 80
    assert "CREDENTIAL_REQUEST" in [
        finding.rule_id for finding in result.findings
    ]


def test_financial_request_detection(engine: SecurityEngine) -> None:
    result = engine.analyze(
        "Please transfer money to this UPI account immediately."
    )

    assert result.verdict == "MALICIOUS"
    assert result.risk_score == 80
    assert "FINANCIAL_REQUEST" in [
        finding.rule_id for finding in result.findings
    ]


def test_impersonation_detection(engine: SecurityEngine) -> None:
    result = engine.analyze(
        "I am from your bank. Please verify your account."
    )

    assert result.verdict == "MALICIOUS"
    assert result.risk_score == 100
    assert "IMPERSONATION_LANGUAGE" in [
        finding.rule_id for finding in result.findings
    ]


def test_multiple_new_security_findings(
    engine: SecurityEngine,
) -> None:
    result = engine.analyze(
        "I am from your bank. "
        "Please send me your password and OTP. "
        "Transfer money to this UPI account."
    )

    assert result.risk_score == 100
    assert result.verdict == "MALICIOUS"

    rule_ids = [
        finding.rule_id
        for finding in result.findings
    ]

    assert "IMPERSONATION_LANGUAGE" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids
    assert "FINANCIAL_REQUEST" in rule_ids
