from typing import Any

from security_engine.exceptions import InvalidInputError


def validate_input(data: Any) -> None:
    """Validate raw security input.

    Accepts plain string content and structured security events.
    """

    if data is None:
        raise InvalidInputError("Input cannot be None.")

    if isinstance(data, str):
        if not data.strip():
            raise InvalidInputError("Input cannot be empty.")
        return

    if isinstance(data, dict):
        if not data:
            raise InvalidInputError("Structured event cannot be empty.")

        if not isinstance(data.get("event_type"), str):
            raise InvalidInputError(
                "Structured event must contain a valid event_type."
            )

        if not data["event_type"].strip():
            raise InvalidInputError(
                "Structured event event_type cannot be empty."
            )
        return

    raise InvalidInputError(
        "Input must be a string or structured event dictionary."
    )
