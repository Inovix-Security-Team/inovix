import pytest
from database.connection import get_db_connection
from database.schema import initialize_schema
from database.models import EventRecord
from database.repositories.events import EventRepository

@pytest.fixture
def event_repo():
    conn = get_db_connection(":memory:")
    initialize_schema(conn)
    repo = EventRepository(conn)
    yield repo
    conn.close()

def test_create_and_get_event(event_repo):
    evt = EventRecord("evt-001", "2026-09-01T10:00:00Z", "auth", "network_monitor", metadata={"ip": "127.0.0.1"})
    event_repo.create_event(evt)
    fetched = event_repo.get_event("evt-001")
    assert fetched is not None
    assert fetched.id == "evt-001"

def test_get_recent_events(event_repo):
    for i in range(3):
        event_repo.create_event(EventRecord(f"evt-00{i}", "2026-09-01T10:00:00Z", "syslog", "test"))
    recent = event_repo.get_recent_events(limit=2)
    assert len(recent) == 2
