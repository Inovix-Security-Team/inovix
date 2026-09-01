import sqlite3
from typing import Optional
from database.models import RiskAssessmentRecord

class RiskRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def save_risk_assessment(self, risk: RiskAssessmentRecord) -> RiskAssessmentRecord:
        query = """
            INSERT INTO risk_assessments (event_id, score, risk_level, verdict)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                score=excluded.score,
                risk_level=excluded.risk_level,
                verdict=excluded.verdict
        """
        with self.conn:
            cursor = self.conn.execute(query, (
                risk.event_id, risk.score, risk.risk_level, risk.verdict
            ))
            risk.id = cursor.lastrowid
        return risk

    def get_risk_for_event(self, event_id: str) -> Optional[RiskAssessmentRecord]:
        query = "SELECT * FROM risk_assessments WHERE event_id = ?"
        cursor = self.conn.execute(query, (event_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return RiskAssessmentRecord(
            id=row["id"], event_id=row["event_id"], score=row["score"],
            risk_level=row["risk_level"], verdict=row["verdict"], created_at=row["created_at"]
        )
