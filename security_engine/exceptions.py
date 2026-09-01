class SecurityEngineError(Exception):
    """Base exception for the security engine."""


class InvalidInputError(SecurityEngineError):
    """Raised when engine input is invalid."""