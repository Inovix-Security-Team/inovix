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
        # Structured telemetry events do not require a "content" field.
        # They are converted into analyzable text by the engine.
        if not data:
            raise InvalidInputError("Structured event cannot be empty.")

        return

    raise InvalidInputError(
        "Input must be a string or structured event dictionary."
    )