import pytest
from database.connection import get_db_connection
from database.schema import initialize_schema
from database.models import EventRecord, RiskAssessmentRecord
from database.repositories.events import EventRepository
from database.repositories.risk import RiskRepository

@pytest.fixture
def repos():
    conn = get_db_connection(":memory:")
    initialize_schema(conn)
    yield EventRepository(conn), RiskRepository(conn)
    conn.close()

def test_save_and_get_risk(repos):
    event_repo, risk_repo = repos
    event_repo.create_event(EventRecord("evt-001", "now", "test", "unit"))
    risk_repo.save_risk_assessment(RiskAssessmentRecord("evt-001", 85, "HIGH", "MALICIOUS"))
    fetched = risk_repo.get_risk_for_event("evt-001")
    assert fetched is not None
    assert fetched.score == 85
