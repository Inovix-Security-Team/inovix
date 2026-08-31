from security_engine.models import Finding

from security_engine.threat_intelligence import (
    LocalThreatIntelligenceProvider,
    ThreatIntelligenceProvider,
)


def test_local_provider_implements_interface() -> None:
    provider = LocalThreatIntelligenceProvider()

    assert isinstance(provider, ThreatIntelligenceProvider)


def test_local_provider_preserves_finding() -> None:
    provider = LocalThreatIntelligenceProvider()

    finding = Finding(
        rule_id="TEST_RULE",
        severity="HIGH",
        reason="Test finding.",
        indicator="test_indicator",
    )

    enriched = provider.enrich(finding)

    assert enriched is finding
    assert enriched.rule_id == "TEST_RULE"
    assert enriched.severity == "HIGH"
    assert enriched.indicator == "test_indicator"


def test_threat_intelligence_is_used_by_engine() -> None:
    from security_engine.engine import SecurityEngine

    engine = SecurityEngine()

    assert engine.threat_intelligence is not None

    result = engine.analyze(
        "Please send me your password and OTP."
    )

    assert result.verdict == "MALICIOUS"
    assert result.risk_score == 80
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "CREDENTIAL_REQUEST"

def test_malicious_local_ioc_enriches_finding() -> None:
    from security_engine.threat_intelligence import (
    IOC,
    IOCStatus,
    IOCType,
    LocalIOCStore,
    LocalThreatIntelligenceProvider,
)

    store = LocalIOCStore()

    ioc = IOC(
        value="203.0.113.10",
        ioc_type=IOCType.IP,
        status=IOCStatus.MALICIOUS,
        source="test-feed",
        confidence=95,
    )

    store.add_ioc(ioc)

    provider = LocalThreatIntelligenceProvider(store)

    finding = Finding(
        rule_id="IP_BASED_URL",
        severity="HIGH",
        reason="URL uses a direct IP address instead of a domain.",
        indicator="ip_based_url",
        value="203.0.113.10",
    )

    enriched = provider.enrich(finding)

    assert enriched.severity == "CRITICAL"
    assert enriched.value == "203.0.113.10"
    assert "malicious" in enriched.reason.lower()

def test_unknown_local_ioc_preserves_finding() -> None:
    from security_engine.threat_intelligence import (
        LocalIOCStore,
        LocalThreatIntelligenceProvider,
    )

    provider = LocalThreatIntelligenceProvider(LocalIOCStore())

    finding = Finding(
        rule_id="IP_BASED_URL",
        severity="HIGH",
        reason="URL uses a direct IP address instead of a domain.",
        indicator="ip_based_url",
        value="203.0.113.10",
    )

    enriched = provider.enrich(finding)

    assert enriched is finding
    assert enriched.severity == "HIGH"