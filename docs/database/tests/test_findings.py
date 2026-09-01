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
    yield EventRepository(conn), FindingRepository(conn), conn
    conn.close()


def test_create_and_retrieve_finding(repos):
    event_repo, finding_repo, _ = repos
    event_repo.create_event(EventRecord(id="evt-001", timestamp="now", event_type="test", source="unit"))

    finding = FindingRecord(
        event_id="evt-001",
        rule_id="RULE-101",
        severity="HIGH",
        reason="Suspicious Credential Request",
        indicator="password_field"
    )
    finding_repo.create_finding(finding)

    findings = finding_repo.get_findings_for_event("evt-001")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_finding_foreign_key_constraint(repos):
    _, finding_repo, _ = repos
    # Attempting to insert finding without matching event must raise IntegrityError
    finding = FindingRecord(
        event_id="non-existent-evt",
        rule_id="RULE-999",
        severity="LOW",
        reason="Test",
        indicator="none"
    )
    with pytest.raises(sqlite3.IntegrityError):
        finding_repo.create_finding(finding)