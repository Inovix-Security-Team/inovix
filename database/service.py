import sqlite3
from typing import List, Optional, Dict, Any

from database.models import (
    EventRecord,
    FindingRecord,
    RiskAssessmentRecord,
)
from database.repositories.events import EventRepository
from database.repositories.findings import FindingRepository
from database.repositories.risk import RiskRepository


class DatabaseService:
    """
    Service layer responsible for coordinating database repositories.

    The service owns the transaction boundary so that an event,
    its findings, and its risk assessment are persisted atomically.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

        self.event_repository = EventRepository(conn)
        self.finding_repository = FindingRepository(conn)
        self.risk_repository = RiskRepository(conn)

    def save_analysis(
        self,
        event: EventRecord,
        findings: List[FindingRecord],
        risk: RiskAssessmentRecord,
    ) -> Dict[str, Any]:
        """
        Persist an event, its findings, and its risk assessment
        in a single transaction.

        If any operation fails, the entire transaction is rolled back.
        """

        if risk.event_id != event.id:
            raise ValueError(
                "Risk assessment event_id must match event.id"
            )

        for finding in findings:
            if finding.event_id != event.id:
                raise ValueError(
                    "Finding event_id must match event.id"
                )

        try:
            saved_event = self.event_repository.create_event(event)

            if saved_event is None:
                raise RuntimeError(
                    f"Failed to save event {event.id}"
                )

            saved_findings = []

            for finding in findings:
                saved_finding = self.finding_repository.create_finding(
                    finding
                )
                saved_findings.append(saved_finding)

            saved_risk = self.risk_repository.save_risk_assessment(risk)

            self.conn.commit()

            return {
                "event": saved_event,
                "findings": saved_findings,
                "risk": saved_risk,
            }

        except Exception:
            self.conn.rollback()
            raise

    def get_analysis(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve the complete analysis associated with an event.
        """

        event = self.event_repository.get_event(event_id)

        if event is None:
            return None

        findings = self.finding_repository.get_findings_for_event(
            event_id
        )

        risk = self.risk_repository.get_risk_for_event(event_id)

        return {
            "event": event,
            "findings": findings,
            "risk": risk,
        }

    def get_recent_events(
        self,
        limit: int = 10,
    ) -> List[EventRecord]:
        """
        Retrieve recent security events.
        """

        return self.event_repository.get_recent_events(limit)

    def get_findings(
        self,
        event_id: str,
    ) -> List[FindingRecord]:
        """
        Retrieve findings associated with an event.
        """

        return self.finding_repository.get_findings_for_event(event_id)

    def get_risk(
        self,
        event_id: str,
    ) -> Optional[RiskAssessmentRecord]:
        """
        Retrieve risk assessment associated with an event.
        """

        return self.risk_repository.get_risk_for_event(event_id)
