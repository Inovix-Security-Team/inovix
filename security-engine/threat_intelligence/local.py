from models import Finding

from threat_intelligence.base import ThreatIntelligenceProvider


class LocalThreatIntelligenceProvider(ThreatIntelligenceProvider):
    """Deterministic local threat-intelligence provider.

    This provider intentionally uses no external services.
    It provides a foundation for future feed/API integrations.
    """

    def enrich(self, finding: Finding) -> Finding:
        """Return the finding unchanged when no local intelligence exists."""
        return finding