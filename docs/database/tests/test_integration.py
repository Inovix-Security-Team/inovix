import pytest
import uuid
from engine import SecurityEngine
from database.connection import get_db_connection
from database.schema import initialize_schema
from database.models import EventRecord, FindingRecord, RiskAssessmentRecord
from database.repositories.events import EventRepository
from database.repositories.findings import FindingRepository
from database.repositories.risk import RiskRepository


def test_security_engine_to_database_flow():
    # 1. Setup DB
    conn = get_db_connection(":memory:")
    initialize_schema(conn)
    event_repo = EventRepository(conn)
    finding_repo = FindingRepository(conn)
    risk_repo = RiskRepository(conn)

    # 2. Analyze threat via engine
    engine = SecurityEngine()
    test_message = "URGENT: Verify your bank credentials immediately at http://fake-login.com"
    engine_result = engine.analyze(test_message)

    # 3. Save Event
    event_id = str(uuid.uuid4())
    event_rec = EventRecord(
        id=event_id,
        timestamp="2026-09-01T20:00:00Z",
        event_type="phishing_attempt",
        source="email_collector",
        metadata={"message_sample": test_message}
    )
    event_repo.create_event(event_rec)

    # 4. Save Findings
    findings_list = engine_result.get("findings", []) if isinstance(engine_result, dict) else getattr(engine_result, "findings", [])
    for idx, f in enumerate(findings_list):
        finding_rec = FindingRecord(
            event_id=event_id,
            rule_id=f.get("rule_id", f"RULE-{idx}") if isinstance(f, dict) else getattr(f, "rule_id", f"RULE-{idx}"),
            severity=f.get("severity", "MEDIUM") if isinstance(f, dict) else getattr(f, "severity", "MEDIUM"),
            reason=f.get("reason", "Suspicious detection") if isinstance(f, dict) else getattr(f, "reason", "Suspicious detection"),
            indicator=f.get("indicator", "url") if isinstance(f, dict) else getattr(f, "indicator", "url")
        )
        finding_repo.create_finding(finding_rec)

    # 5. Save Risk Result
    risk_score = engine_result.get("risk_result", {}).get("risk_score", 75) if isinstance(engine_result, dict) else getattr(engine_result, "risk_score", 75)
    risk_rec = RiskAssessmentRecord(
        event_id=event_id,
        score=risk_score,
        risk_level="HIGH" if risk_score >= 60 else "LOW",
        verdict="MALICIOUS" if risk_score >= 60 else "BENIGN"
    )
    risk_repo.save_risk_assessment(risk_rec)

    # 6. Verify Retrieval
    db_evt = event_repo.get_event(event_id)
    db_findings = finding_repo.get_findings_for_event(event_id)
    db_risk = risk_repo.get_risk_for_event(event_id)

    assert db_evt is not None
    assert db_risk.score == risk_score
    assert len(db_findings) == len(findings_list)

    conn.close()