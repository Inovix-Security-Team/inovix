from typing import Any

from models import NormalizedEvent
from utils.validation import validate_input


def normalize_input(
    content: Any,
    source: str = "unknown",
    event_type: str = "text",
    metadata: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """Validate and normalize a raw security event."""

    validate_input(content)

    normalized_content = content.strip()

    return NormalizedEvent(
        content=normalized_content,
        source=source.strip() if source else "unknown",
        event_type=event_type.strip() if event_type else "text",
        metadata=metadata or {},
    )