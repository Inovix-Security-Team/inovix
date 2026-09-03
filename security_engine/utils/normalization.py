from typing import Any

from security_engine.models import NormalizedEvent
from security_engine.utils.validation import validate_input


def normalize_input(
    content: Any,
    source: str = "unknown",
    event_type: str = "text",
    metadata: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """Validate and normalize raw security input."""

    validate_input(content)

    if isinstance(content, dict):
        normalized_source = content.get("source", source)
        normalized_event_type = content.get("event_type", event_type)

        normalized_metadata = dict(metadata or {})
        normalized_metadata.update(
            content.get("metadata", {})
            if isinstance(content.get("metadata"), dict)
            else {}
        )
        normalized_metadata["event"] = dict(content)

        if "content" in content:
            raw_content = content["content"]
        else:
            fields = []
            for key, value in content.items():
                if key == "metadata":
                    continue

                if isinstance(value, (dict, list, tuple)):
                    value = str(value)

                fields.append(f"{key}: {value}")

            raw_content = "\n".join(fields)

        return NormalizedEvent(
            content=raw_content.strip(),
            source=(
                normalized_source.strip()
                if isinstance(normalized_source, str)
                and normalized_source.strip()
                else "unknown"
            ),
            event_type=(
                normalized_event_type.strip()
                if isinstance(normalized_event_type, str)
                and normalized_event_type.strip()
                else "text"
            ),
            metadata=normalized_metadata,
        )

    return NormalizedEvent(
        content=content.strip(),
        source=source.strip() if source else "unknown",
        event_type=event_type.strip() if event_type else "text",
        metadata=metadata or {},
    )
