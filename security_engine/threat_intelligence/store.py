import sqlite3
from datetime import datetime

from security_engine.threat_intelligence.models import (
    IOC,
    IOCStatus,
    IOCType,
)

class LocalIOCStore:
    """SQLite-backed local threat-intelligence IOC storage."""

    def __init__(self, database_path: str = ":memory:") -> None:
        self.database_path = database_path

        # Keep one connection alive for in-memory databases.
        self._connection = sqlite3.connect(self.database_path)

        self._initialize()

    def _initialize(self) -> None:
        """Create the local IOC table when it does not already exist."""

        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                expires_at TEXT,
                PRIMARY KEY (value, ioc_type)
            )
            """
        )

        self._connection.commit()

    def add_ioc(self, ioc: IOC) -> None:
        """Insert or replace an IOC."""

        normalized_value = self._normalize_value(ioc.value)

        self._connection.execute(
            """
            INSERT OR REPLACE INTO iocs (
                value,
                ioc_type,
                status,
                source,
                confidence,
                first_seen,
                last_seen,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_value,
                ioc.ioc_type.value,
                ioc.status.value,
                ioc.source,
                ioc.confidence,
                self._serialize_datetime(ioc.first_seen),
                self._serialize_datetime(ioc.last_seen),
                self._serialize_datetime(ioc.expires_at),
            ),
        )

        self._connection.commit()

    def lookup_ioc(
        self,
        value: str,
        ioc_type: IOCType,
    ) -> IOC | None:
        """Look up an IOC by normalized value and type."""

        normalized_value = self._normalize_value(value)

        row = self._connection.execute(
            """
            SELECT
                value,
                ioc_type,
                status,
                source,
                confidence,
                first_seen,
                last_seen,
                expires_at
            FROM iocs
            WHERE value = ? AND ioc_type = ?
            """,
            (
                normalized_value,
                ioc_type.value,
            ),
        ).fetchone()

        if row is None:
            return None

        return IOC(
            value=row[0],
            ioc_type=IOCType(row[1]),
            status=IOCStatus(row[2]),
            source=row[3],
            confidence=row[4],
            first_seen=self._deserialize_datetime(row[5]),
            last_seen=self._deserialize_datetime(row[6]),
            expires_at=self._deserialize_datetime(row[7]),
        )

    def lookup_active_ioc(
        self,
        value: str,
        ioc_type: IOCType,
        now: datetime | None = None,
    ) -> IOC | None:
        """Return an IOC only when it is not expired."""

        ioc = self.lookup_ioc(value, ioc_type)

        if ioc is None:
            return None

        if ioc.is_expired(now):
            return None

        return ioc

    def get_ioc_status(
        self,
        value: str,
        ioc_type: IOCType,
        now: datetime | None = None,
    ) -> IOCStatus | None:
        """Return the status of an active IOC."""

        ioc = self.lookup_active_ioc(
            value,
            ioc_type,
            now,
        )

        if ioc is None:
            return None

        return ioc.status

    def remove_ioc(
        self,
        value: str,
        ioc_type: IOCType,
    ) -> bool:
        """Remove an IOC and return whether it existed."""

        normalized_value = self._normalize_value(value)

        cursor = self._connection.execute(
            """
            DELETE FROM iocs
            WHERE value = ? AND ioc_type = ?
            """,
            (
                normalized_value,
                ioc_type.value,
            ),
        )

        self._connection.commit()

        return cursor.rowcount > 0

    def close(self) -> None:
        """Close the underlying SQLite connection."""

        self._connection.close()

    @staticmethod
    def _normalize_value(value: str) -> str:
        """Normalize IOC values for deterministic lookup."""

        return value.strip().lower()

    @staticmethod
    def _serialize_datetime(
        value: datetime | None,
    ) -> str | None:
        """Serialize a datetime for SQLite storage."""

        return value.isoformat() if value is not None else None

    @staticmethod
    def _deserialize_datetime(
        value: str | None,
    ) -> datetime | None:
        """Deserialize a stored SQLite datetime."""

        return datetime.fromisoformat(value) if value else None