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
    event = EventRecord(
        "evt-001",
        "2026-09-01T10:00:00Z",
        "auth",
        "network_monitor",
        content_hash="abc123",
        metadata={"ip": "127.0.0.1", "port": 443},
    )

    created = event_repo.create_event(event)

    assert created is not None
    assert created.id == "evt-001"
    assert created.timestamp == "2026-09-01T10:00:00Z"
    assert created.event_type == "auth"
    assert created.source == "network_monitor"
    assert created.content_hash == "abc123"
    assert created.metadata == {
        "ip": "127.0.0.1",
        "port": 443,
    }

    fetched = event_repo.get_event("evt-001")

    assert fetched is not None
    assert fetched.id == "evt-001"
    assert fetched.event_type == "auth"
    assert fetched.source == "network_monitor"
    assert fetched.metadata == {
        "ip": "127.0.0.1",
        "port": 443,
    }


def test_get_event_returns_none_for_unknown_event(event_repo):
    result = event_repo.get_event("does-not-exist")

    assert result is None


def test_get_recent_events(event_repo):
    for i in range(3):
        event_repo.create_event(
            EventRecord(
                f"evt-00{i}",
                f"2026-09-01T10:0{i}:00Z",
                "syslog",
                "test",
                metadata={"index": i},
            )
        )

    recent = event_repo.get_recent_events(limit=2)

    assert len(recent) == 2
    assert all(isinstance(event, EventRecord) for event in recent)
    assert all(event.event_type == "syslog" for event in recent)
    assert all(event.source == "test" for event in recent)


def test_get_recent_events_returns_empty_for_empty_database(event_repo):
    recent = event_repo.get_recent_events()

    assert recent == []


def test_get_recent_events_respects_limit(event_repo):
    for i in range(5):
        event_repo.create_event(
            EventRecord(
                f"evt-{i:03d}",
                "2026-09-01T10:00:00Z",
                "test",
                "unit",
            )
        )

    recent = event_repo.get_recent_events(limit=3)

    assert len(recent) == 3
