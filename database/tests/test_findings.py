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
    event_repo.create_event(EventRecord("evt-001", "now", "test", "unit"))
    finding_repo.create_finding(FindingRecord("evt-001", "RULE-101", "HIGH", "Reason", "indicator"))
    findings = finding_repo.get_findings_for_event("evt-001")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"

def test_finding_foreign_key_constraint(repos):
    _, finding_repo = repos
    with pytest.raises(sqlite3.IntegrityError):
        finding_repo.create_finding(FindingRecord("non-existent", "RULE-999", "LOW", "Test", "none"))
