import pytest
import sqlite3

from database.connection import get_db_connection
from database.schema import initialize_schema
from database.models import EventRecord, FindingRecord
from database.repositories.events import EventRepository
from database.repositories.findings import FindingRepository


@pytest.fixture
def repos():
    conn = get_db_connection(":memory:")
    initialize_schema(conn)

    yield EventRepository(conn), FindingRepository(conn)

    conn.close()


def test_create_and_retrieve_finding(repos):
    event_repo, finding_repo = repos

    event_repo.create_event(
        EventRecord(
            "evt-001",
            "2026-09-01T10:00:00Z",
            "test",
            "unit",
        )
    )

    finding = FindingRecord(
        "evt-001",
        "RULE-101",
        "HIGH",
        "Suspicious activity detected",
        "192.168.1.10",
    )

    created = finding_repo.create_finding(finding)

    assert created.id is not None
    assert created.event_id == "evt-001"
    assert created.rule_id == "RULE-101"
    assert created.severity == "HIGH"
    assert created.reason == "Suspicious activity detected"
    assert created.indicator == "192.168.1.10"

    findings = finding_repo.get_findings_for_event("evt-001")

    assert len(findings) == 1
    assert findings[0].event_id == "evt-001"
    assert findings[0].rule_id == "RULE-101"
    assert findings[0].severity == "HIGH"
    assert findings[0].reason == "Suspicious activity detected"
    assert findings[0].indicator == "192.168.1.10"


def test_multiple_findings_for_event(repos):
    event_repo, finding_repo = repos

    event_repo.create_event(
        EventRecord(
            "evt-001",
            "2026-09-01T10:00:00Z",
            "test",
            "unit",
        )
    )

    finding_repo.create_finding(
        FindingRecord(
            "evt-001",
            "RULE-101",
            "HIGH",
            "Malicious IP",
            "10.0.0.1",
        )
    )

    finding_repo.create_finding(
        FindingRecord(
            "evt-001",
            "RULE-102",
            "MEDIUM",
            "Suspicious domain",
            "example.test",
        )
    )

    findings = finding_repo.get_findings_for_event("evt-001")

    assert len(findings) == 2
    assert findings[0].rule_id == "RULE-101"
    assert findings[1].rule_id == "RULE-102"


def test_get_findings_for_unknown_event(repos):
    _, finding_repo = repos

    findings = finding_repo.get_findings_for_event("does-not-exist")

    assert findings == []


def test_finding_foreign_key_constraint(repos):
    _, finding_repo = repos

    with pytest.raises(sqlite3.IntegrityError):
        finding_repo.create_finding(
            FindingRecord(
                "non-existent",
                "RULE-999",
                "LOW",
                "Test",
                "none",
            )
        )
