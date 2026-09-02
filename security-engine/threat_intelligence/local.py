from dataclasses import replace

from security_engine.models import Finding
from security_engine.threat_intelligence.base import (
    ThreatIntelligenceProvider,
)
from security_engine.threat_intelligence.models import IOCStatus, IOCType
from security_engine.threat_intelligence.store import LocalIOCStore

class LocalThreatIntelligenceProvider(ThreatIntelligenceProvider):
    """Threat-intelligence provider backed by local IOC storage."""

    def __init__(
        self,
        store: LocalIOCStore | None = None,
    ) -> None:
        self.store = store or LocalIOCStore()

    def enrich(self, finding: Finding) -> Finding:
        """Enrich a finding when its value matches a local IOC."""

        ioc_type = self._indicator_type(finding.indicator)

        if ioc_type is None or finding.value is None:
            return finding

        ioc = self.store.lookup_active_ioc(
            finding.value,
            ioc_type,
        )

        if ioc is None:
            return finding

        if ioc.status == IOCStatus.MALICIOUS:
            return replace(
                finding,
                severity="CRITICAL",
                reason=(
                    f"{finding.reason} "
                    f"Local threat intelligence identifies this "
                    f"indicator as malicious "
                    f"(source={ioc.source}, confidence={ioc.confidence})."
                ),
            )

        if ioc.status == IOCStatus.SUSPICIOUS:
            return replace(
                finding,
                severity="HIGH",
                reason=(
                    f"{finding.reason} "
                    f"Local threat intelligence identifies this "
                    f"indicator as suspicious "
                    f"(source={ioc.source}, confidence={ioc.confidence})."
                ),
            )

        return finding

    @staticmethod
    def _indicator_type(indicator: str) -> IOCType | None:
        """Map engine indicators to supported IOC types."""

        indicator_types = {
            "ip_based_url": IOCType.IP,
            "url": IOCType.URL,
            "domain": IOCType.DOMAIN,
            "hash": IOCType.HASH,
        }

        return indicator_types.get(indicator)
