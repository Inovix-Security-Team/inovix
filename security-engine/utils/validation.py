from typing import Any

from exceptions import InvalidInputError


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

        if "event_type" not in data:
            raise InvalidInputError(
                "Structured event must contain an event_type."
            )

        return

    raise InvalidInputError(
        "Input must be a string or structured event dictionary."
    )
