import sqlite3


CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    content_hash TEXT,
    metadata TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    indicator TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
);
"""

CREATE_RISK_ASSESSMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS risk_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    verdict TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
);
"""

CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_findings_event_id ON findings(event_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_event_id ON risk_assessments(event_id);
"""


def initialize_schema(conn: sqlite3.Connection) -> None:
    """Initializes the database schema non-destructively."""
    with conn:
        conn.execute(CREATE_EVENTS_TABLE)
        conn.execute(CREATE_FINDINGS_TABLE)
        conn.execute(CREATE_RISK_ASSESSMENTS_TABLE)
        conn.executescript(CREATE_INDEXES)