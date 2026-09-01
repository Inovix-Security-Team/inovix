import pytest
import socket
from database.connection import get_db_connection
from database.schema import initialize_schema
from database.models import EventRecord
from database.repositories.events import EventRepository

def test_database_operates_without_network(monkeypatch):
    def guarded_socket(*args, **kwargs):
        raise OSError("Network isolated")
    monkeypatch.setattr(socket, "socket", guarded_socket)

    conn = get_db_connection(":memory:")
    initialize_schema(conn)
    repo = EventRepository(conn)
    repo.create_event(EventRecord("offline-01", "now", "test", "offline_check"))

    assert repo.get_event("offline-01") is not None
    conn.close()
