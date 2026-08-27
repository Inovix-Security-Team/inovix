from abc import ABC, abstractmethod


class Detector(ABC):
    """Interface for security detection modules."""

    @abstractmethod
    def detect(self, analysis: dict) -> dict:
        """Detect security indicators from analyzer output."""
        raise NotImplementedError