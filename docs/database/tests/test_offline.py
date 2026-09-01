import pytest
import socket
from database.connection import get_db_connection
from database.schema import initialize_schema
from database.models import EventRecord
from database.repositories.events import EventRepository


def test_database_operates_without_network(monkeypatch):
    """Proves DB operations work even if network calls strictly fail."""
    def guarded_socket(*args, **kwargs):
        raise OSError("Network isolated - Offline test active")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    conn = get_db_connection(":memory:")
    initialize_schema(conn)
    repo = EventRepository(conn)

    evt = EventRecord(id="offline-01", timestamp="now", event_type="test", source="offline_check")
    repo.create_event(evt)

    retrieved = repo.get_event("offline-01")
    assert retrieved is not None
    assert retrieved.id == "offline-01"
    conn.close()