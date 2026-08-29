from abc import ABC, abstractmethod

from models import Finding


class Detector(ABC):
    """Interface for security detection modules."""

    @abstractmethod
    def detect(self, analysis: dict) -> list[Finding]:
        """Generate security findings from analyzer output."""
        raise NotImplementedError