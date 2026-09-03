import sqlite3
from pathlib import Path
from typing import Optional, Union

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "inovix_local.db"

def get_db_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    path = str(db_path) if db_path else str(DEFAULT_DB_PATH)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn
