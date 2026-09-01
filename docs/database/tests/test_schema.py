import pytest
from database.connection import get_db_connection
from database.schema import initialize_schema


@pytest.fixture
def db_conn():
    conn = get_db_connection(":memory:")
    initialize_schema(conn)
    yield conn
    conn.close()


def test_schema_creates_tables(db_conn):
    cursor = db_conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row["name"] for row in cursor.fetchall()]
    assert "events" in tables
    assert "findings" in tables
    assert "risk_assessments" in tables


def test_idempotent_schema_initialization(db_conn):
    # Ensure re-running schema initialization doesn't throw errors
    initialize_schema(db_conn)
    initialize_schema(db_conn)