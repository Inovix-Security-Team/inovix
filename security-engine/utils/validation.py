from typing import Any

from security_engine.exceptions import InvalidInputError

def validate_input(data: Any) -> None:
    """Validate raw input before analysis."""

    if data is None:
        raise InvalidInputError("Input cannot be None.")

    if not isinstance(data, str):
        raise InvalidInputError("Input must be a string.")

    if not data.strip():
        raise InvalidInputError("Input cannot be empty.")
