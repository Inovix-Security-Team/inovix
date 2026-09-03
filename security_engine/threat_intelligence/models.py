from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum


class IOCType(str, Enum):
    """Supported indicator-of-compromise types."""

    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"


class IOCStatus(str, Enum):
    """Threat-intelligence classification."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class IOC:
    """A locally stored indicator of compromise."""

    value: str
    ioc_type: IOCType
    status: IOCStatus
    source: str = "local"
    confidence: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True when the IOC has passed its expiration time."""

        if self.expires_at is None:
            return False

        current_time = now or datetime.now(UTC)
        return current_time >= self.expires_at
