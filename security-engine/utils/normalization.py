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

    if isinstance(content, dict):
        raw_content = content["content"]
        normalized_source = content.get("source", source)
        normalized_event_type = content.get("event_type", event_type)
        normalized_metadata = content.get("metadata", metadata)

        return NormalizedEvent(
            content=raw_content.strip(),
            source=(
                normalized_source.strip()
                if isinstance(normalized_source, str) and normalized_source
                else "unknown"
            ),
            event_type=(
                normalized_event_type.strip()
                if isinstance(normalized_event_type, str)
                and normalized_event_type
                else "text"
            ),
            metadata=(
                normalized_metadata
                if isinstance(normalized_metadata, dict)
                else {}
            ),
        )

    return NormalizedEvent(
        content=content.strip(),
        source=source.strip() if source else "unknown",
        event_type=event_type.strip() if event_type else "text",
        metadata=metadata or {},
    )
