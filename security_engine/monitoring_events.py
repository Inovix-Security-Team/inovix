from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MonitoringEvent:
    """Standard event produced by system monitoring collectors."""

    event_type: str
    source: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the monitoring event to a dictionary."""

        return {
            "event_type": self.event_type,
            "source": self.source,
            "timestamp": self.timestamp,
            "data": self.data,
        }