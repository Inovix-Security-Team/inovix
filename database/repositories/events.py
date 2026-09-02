import sqlite3
import json
from typing import Optional, List

from database.models import EventRecord


class EventRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create_event(self, event: EventRecord) -> Optional[EventRecord]:
        query = """
            INSERT INTO events (
                id,
                timestamp,
                event_type,
                source,
                content_hash,
                metadata
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """

        metadata_str = (
            json.dumps(event.metadata)
            if isinstance(event.metadata, dict)
            else event.metadata
        )

        self.conn.execute(
            query,
            (
                event.id,
                event.timestamp,
                event.event_type,
                event.source,
                event.content_hash,
                metadata_str,
            ),
        )

        return self.get_event(event.id)

    def get_event(self, event_id: str) -> Optional[EventRecord]:
        query = """
            SELECT *
            FROM events
            WHERE id = ?
        """

        cursor = self.conn.execute(query, (event_id,))
        row = cursor.fetchone()

        if not row:
            return None

        meta = row["metadata"]
        parsed_meta = json.loads(meta) if meta else None

        return EventRecord(
            id=row["id"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            source=row["source"],
            content_hash=row["content_hash"],
            metadata=parsed_meta,
            created_at=row["created_at"],
        )

    def get_recent_events(self, limit: int = 10) -> List[EventRecord]:
        query = """
            SELECT *
            FROM events
            ORDER BY created_at DESC
            LIMIT ?
        """

        cursor = self.conn.execute(query, (limit,))
        rows = cursor.fetchall()

        events = []

        for row in rows:
            meta = row["metadata"]
            parsed_meta = json.loads(meta) if meta else None

            events.append(
                EventRecord(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    source=row["source"],
                    content_hash=row["content_hash"],
                    metadata=parsed_meta,
                    created_at=row["created_at"],
                )
            )

        return events
