import pytest
import uuid
from security_engine.engine import SecurityEngine
from database.connection import get_db_connection
from database.schema import initialize_schema
from database.models import EventRecord, FindingRecord, RiskAssessmentRecord
from database.repositories.events import EventRepository
from database.repositories.findings import FindingRepository
from database.repositories.risk import RiskRepository

def test_security_engine_to_database_flow():
    conn = get_db_connection(":memory:")
    initialize_schema(conn)
    event_repo, finding_repo, risk_repo = EventRepository(conn), FindingRepository(conn), RiskRepository(conn)

    engine = SecurityEngine()
    engine_result = engine.analyze("Verify credentials immediately")

    event_id = str(uuid.uuid4())
    event_repo.create_event(EventRecord(event_id, "2026-09-01T20:00:00Z", "phishing", "collector"))
    risk_repo.save_risk_assessment(RiskAssessmentRecord(event_id, 75, "HIGH", "MALICIOUS"))

    assert event_repo.get_event(event_id) is not None
    assert risk_repo.get_risk_for_event(event_id).score == 75
    conn.close()

