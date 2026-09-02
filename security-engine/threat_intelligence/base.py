from abc import ABC, abstractmethod

from models import Finding


class ThreatIntelligenceProvider(ABC):
    """Interface for threat-intelligence enrichment providers."""

    @abstractmethod
    def enrich(self, finding: Finding) -> Finding:
        """Enrich a security finding with threat-intelligence context."""
        raise NotImplementedError