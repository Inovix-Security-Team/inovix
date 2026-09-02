import uuid

import pytest

from database.connection import get_db_connection
from database.models import (
    EventRecord,
    FindingRecord,
    RiskAssessmentRecord,
)
from database.schema import initialize_schema
from database.service import DatabaseService


def create_service():
    conn = get_db_connection(":memory:")
    initialize_schema(conn)

    return conn, DatabaseService(conn)


def create_event(event_id):
    return EventRecord(
        id=event_id,
        timestamp="2026-09-02T20:00:00Z",
        event_type="phishing",
        source="email",
        content_hash="abc123",
        metadata={"subject": "Urgent verification"},
    )


def create_finding(event_id, rule_id="RULE-001"):
    return FindingRecord(
        event_id=event_id,
        rule_id=rule_id,
        severity="HIGH",
        reason="Suspicious credential request",
        indicator="https://malicious.example/login",
    )


def create_risk(event_id):
    return RiskAssessmentRecord(
        event_id=event_id,
        score=85,
        risk_level="HIGH",
        verdict="MALICIOUS",
    )


def test_save_analysis_persists_complete_analysis():
    conn, service = create_service()

    event_id = str(uuid.uuid4())

    event = create_event(event_id)

    findings = [
        create_finding(event_id, "RULE-001"),
        create_finding(event_id, "RULE-002"),
    ]

    risk = create_risk(event_id)

    result = service.save_analysis(event, findings, risk)

    assert result["event"].id == event_id
    assert len(result["findings"]) == 2
    assert result["risk"].score == 85

    analysis = service.get_analysis(event_id)

    assert analysis is not None
    assert analysis["event"].event_type == "phishing"
    assert len(analysis["findings"]) == 2
    assert analysis["risk"].risk_level == "HIGH"

    conn.close()


def test_save_analysis_rolls_back_when_finding_fails(monkeypatch):
    conn, service = create_service()

    event_id = str(uuid.uuid4())

    event = create_event(event_id)

    findings = [
        create_finding(event_id, "RULE-001"),
        create_finding(event_id, "RULE-002"),
    ]

    risk = create_risk(event_id)

    original_create_finding = (
        service.finding_repository.create_finding
    )

    call_count = 0

    def failing_create_finding(finding):
        nonlocal call_count

        call_count += 1

        if call_count == 2:
            raise RuntimeError("Simulated database failure")

        return original_create_finding(finding)

    monkeypatch.setattr(
        service.finding_repository,
        "create_finding",
        failing_create_finding,
    )

    with pytest.raises(RuntimeError, match="Simulated database failure"):
        service.save_analysis(event, findings, risk)

    assert service.event_repository.get_event(event_id) is None
    assert service.finding_repository.get_findings_for_event(event_id) == []
    assert service.risk_repository.get_risk_for_event(event_id) is None

    conn.close()


def test_save_analysis_rejects_mismatched_risk_event():
    conn, service = create_service()

    event_id = str(uuid.uuid4())
    different_event_id = str(uuid.uuid4())

    event = create_event(event_id)
    risk = create_risk(different_event_id)

    with pytest.raises(
        ValueError,
        match="Risk assessment event_id must match event.id",
    ):
        service.save_analysis(event, [], risk)

    assert service.event_repository.get_event(event_id) is None

    conn.close()


def test_save_analysis_rejects_mismatched_finding_event():
    conn, service = create_service()

    event_id = str(uuid.uuid4())
    different_event_id = str(uuid.uuid4())

    event = create_event(event_id)
    finding = create_finding(different_event_id)
    risk = create_risk(event_id)

    with pytest.raises(
        ValueError,
        match="Finding event_id must match event.id",
    ):
        service.save_analysis(event, [finding], risk)

    assert service.event_repository.get_event(event_id) is None

    conn.close()


def test_get_analysis_returns_none_for_unknown_event():
    conn, service = create_service()

    result = service.get_analysis(str(uuid.uuid4()))

    assert result is None

    conn.close()


def test_get_recent_events_delegates_to_repository():
    conn, service = create_service()

    event_id = str(uuid.uuid4())

    event = create_event(event_id)
    service.save_analysis(
        event,
        [],
        create_risk(event_id),
    )

    events = service.get_recent_events(limit=10)

    assert len(events) == 1
    assert events[0].id == event_id
    assert events[0].event_type == "phishing"

    conn.close()


def test_get_findings_and_risk():
    conn, service = create_service()

    event_id = str(uuid.uuid4())

    event = create_event(event_id)
    finding = create_finding(event_id)
    risk = create_risk(event_id)

    service.save_analysis(event, [finding], risk)

    findings = service.get_findings(event_id)
    saved_risk = service.get_risk(event_id)

    assert len(findings) == 1
    assert findings[0].rule_id == "RULE-001"

    assert saved_risk is not None
    assert saved_risk.score == 85

    conn.close()
