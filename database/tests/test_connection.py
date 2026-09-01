import sqlite3
from database.connection import get_db_connection

def test_in_memory_connection():
    conn = get_db_connection(":memory:")
    assert isinstance(conn, sqlite3.Connection)
    cursor = conn.execute("PRAGMA foreign_keys;")
    assert cursor.fetchone()[0] == 1
    conn.close()

def test_connection_reopen(tmp_path):
    db_file = tmp_path / "test.db"
    conn1 = get_db_connection(db_file)
    conn1.execute("CREATE TABLE t (id INT);")
    conn1.commit()
    conn1.close()

    conn2 = get_db_connection(db_file)
    cursor = conn2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='t';")
    assert cursor.fetchone() is not None
    conn2.close()
