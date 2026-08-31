import json
from pathlib import Path

import pytest

from security_engine.engine import SecurityEngine
from security_engine.exceptions import InvalidInputError


@pytest.fixture
def test_events():
    data_path = Path(__file__).parent.parent / "test-data" / "events.json"

    with open(data_path, "r", encoding="utf-8") as file:
        return json.load(file)


@pytest.fixture
def engine():
    return SecurityEngine()


def test_pipeline_scenario_a_safe(engine, test_events):
    """Scenario A — Safe login event."""
    event = test_events["normal_login"]

    result = engine.analyze(
        "User login successful.",
        source=event["source_ip"],
        event_type=event["event_type"],
        metadata={
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "user": event["user"],
            "status": event["status"],
        },
    )

    assert result.risk_score == 0
    assert result.verdict == "SAFE"
    assert result.findings == []


def test_pipeline_scenario_b_credential_request(engine, test_events):
    """Scenario B — Credential request detection."""
    event = test_events["credential_request"]

    result = engine.analyze(
        event["message"],
        source=event["source_ip"],
        event_type=event["event_type"],
        metadata={
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
        },
    )

    assert result.risk_score == 80
    assert result.verdict == "MALICIOUS"

    assert any(
        finding.rule_id == "CREDENTIAL_REQUEST"
        for finding in result.findings
    )


def test_pipeline_scenario_c_multiple_findings(engine, test_events):
    """Scenario C — Multiple independent security indicators."""
    event = test_events["multiple_findings"]

    result = engine.analyze(
        event["message"],
        source=event["source_ip"],
        event_type=event["event_type"],
        metadata={
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
        },
    )

    assert len(result.findings) >= 2
    assert len(result.indicators) >= 2

    rule_ids = {finding.rule_id for finding in result.findings}

    assert "URL_PRESENT" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids

    assert 0 <= result.risk_score <= 100
    assert result.risk_score == 100
    assert result.verdict == "MALICIOUS"


def test_pipeline_scenario_d_invalid_input(engine):
    """Scenario D — Invalid input must be rejected cleanly."""
    with pytest.raises(InvalidInputError):
        engine.analyze("")
