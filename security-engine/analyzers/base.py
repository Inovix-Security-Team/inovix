from abc import ABC, abstractmethod

from security_engine.models import AnalysisInput
class Analyzer(ABC):
    """Interface for all security analyzers."""

    @abstractmethod
    def analyze(self, data: AnalysisInput) -> dict:
        """Analyze normalized input."""
        raise NotImplementedError
