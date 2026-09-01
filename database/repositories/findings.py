import sqlite3
from typing import List
from database.models import FindingRecord

class FindingRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create_finding(self, finding: FindingRecord) -> FindingRecord:
        query = """
            INSERT INTO findings (event_id, rule_id, severity, reason, indicator)
            VALUES (?, ?, ?, ?, ?)
        """
        with self.conn:
            cursor = self.conn.execute(query, (
                finding.event_id, finding.rule_id, finding.severity,
                finding.reason, finding.indicator
            ))
            finding.id = cursor.lastrowid
        return finding

    def get_findings_for_event(self, event_id: str) -> List[FindingRecord]:
        query = "SELECT * FROM findings WHERE event_id = ?"
        cursor = self.conn.execute(query, (event_id,))
        return [
            FindingRecord(
                id=row["id"], event_id=row["event_id"], rule_id=row["rule_id"],
                severity=row["severity"], reason=row["reason"],
                indicator=row["indicator"], created_at=row["created_at"]
            )
            for row in cursor.fetchall()
        ]
