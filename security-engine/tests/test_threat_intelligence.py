from security_engine.models import Finding

from threat_intelligence import (
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
    from engine import SecurityEngine

    engine = SecurityEngine()

    assert engine.threat_intelligence is not None

    result = engine.analyze(
        "Please send me your password and OTP."
    )

    assert result.verdict == "MALICIOUS"
    assert result.risk_score == 80
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "CREDENTIAL_REQUEST"
