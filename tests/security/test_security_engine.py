import pytest
import json
from pathlib import Path
from types import SimpleNamespace
from engine import SecurityEngine
from utils.risk_scoring import calculate_risk_score

@pytest.fixture
def events():
    fixture_path = Path(__file__).resolve().parent.parent / "test-data" / "events.json"
    with open(fixture_path, "r") as f:
        return json.load(f)

def test_engine_false_positive_handling(events):
    """Verify benign messages are handled and engine runs without crashing."""
    engine = SecurityEngine()
    sample1 = events["false_positive_password_policy"]
    sample2 = events["false_positive_admin_banking"]
    
    msg1 = sample1.get("message", "")
    msg2 = sample2.get("message", "")
    
    res1 = engine.analyze(msg1)
    res2 = engine.analyze(msg2)
    
    # Assert structural engine output validity
    assert res1 is not None
    assert res2 is not None

def get_risk_band(score: int) -> str:
    """Helper mapping calculated numeric scores to expected risk bands."""
    if score < 30:
        return "Low"
    elif score < 60:
        return "Medium"
    elif score < 75:
        return "High"
    return "Critical"

def create_test_finding(severity: str):
    """Create a lightweight mock finding object with just a severity attribute."""
    return SimpleNamespace(severity=severity)

@pytest.mark.parametrize("findings_severities, expected_band", [
    ([], "Low"),
    (["LOW"], "Low"),
    (["MEDIUM"], "Medium"),
    (["CRITICAL"], "Critical"),
    (["HIGH", "HIGH"], "Critical"),
])
def test_risk_score_boundaries(findings_severities, expected_band):
    """Test risk score calculation from mock Finding objects."""
    findings = [create_test_finding(sev) for sev in findings_severities]
    
    score = calculate_risk_score(findings)
    band = get_risk_band(score)
    assert band == expected_band

def test_multi_indicator_scenarios(events):
    """Test combined threat scenario detection."""
    engine = SecurityEngine()
    combined = events["multiple_findings"]
    
    msg = combined.get("message", str(combined))
    res = engine.analyze(msg)
    
    score = res.get("risk_result", {}).get("risk_score", 0) if isinstance(res, dict) else res.risk_score
    assert score >= 60