from dataclasses import replace

from security_engine.models import Finding
from security_engine.threat_intelligence.base import (
    ThreatIntelligenceProvider,
)
from security_engine.threat_intelligence.models import IOCStatus, IOCType
from security_engine.threat_intelligence.store import LocalIOCStore
    """Deterministic local threat-intelligence provider.

    This provider intentionally uses no external services.
    It provides a foundation for future feed/API integrations.
    """

    def enrich(self, finding: Finding) -> Finding:
        """Return the finding unchanged when no local intelligence exists."""
        return finding
