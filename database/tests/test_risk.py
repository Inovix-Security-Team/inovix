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

    event_repo.create_event(
        EventRecord(
            "evt-001",
            "2026-09-01T10:00:00Z",
            "test",
            "unit",
        )
    )

    risk = RiskAssessmentRecord(
        "evt-001",
        85,
        "HIGH",
        "MALICIOUS",
    )

    saved = risk_repo.save_risk_assessment(risk)

    assert saved is not None
    assert saved.event_id == "evt-001"
    assert saved.score == 85
    assert saved.risk_level == "HIGH"
    assert saved.verdict == "MALICIOUS"
    assert saved.id is not None

    fetched = risk_repo.get_risk_for_event("evt-001")

    assert fetched is not None
    assert fetched.event_id == "evt-001"
    assert fetched.score == 85
    assert fetched.risk_level == "HIGH"
    assert fetched.verdict == "MALICIOUS"


def test_get_risk_for_unknown_event(repos):
    _, risk_repo = repos

    result = risk_repo.get_risk_for_event("does-not-exist")

    assert result is None


def test_risk_assessment_upsert(repos):
    event_repo, risk_repo = repos

    event_repo.create_event(
        EventRecord(
            "evt-001",
            "2026-09-01T10:00:00Z",
            "test",
            "unit",
        )
    )

    first = risk_repo.save_risk_assessment(
        RiskAssessmentRecord(
            "evt-001",
            40,
            "MEDIUM",
            "SUSPICIOUS",
        )
    )

    second = risk_repo.save_risk_assessment(
        RiskAssessmentRecord(
            "evt-001",
            95,
            "CRITICAL",
            "MALICIOUS",
        )
    )

    assert second.id == first.id
    assert second.score == 95
    assert second.risk_level == "CRITICAL"
    assert second.verdict == "MALICIOUS"

    fetched = risk_repo.get_risk_for_event("evt-001")

    assert fetched is not None
    assert fetched.id == first.id
    assert fetched.score == 95
    assert fetched.risk_level == "CRITICAL"
    assert fetched.verdict == "MALICIOUS"
