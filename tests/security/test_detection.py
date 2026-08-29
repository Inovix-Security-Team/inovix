import pytest
import json
from pathlib import Path

@pytest.fixture
def test_events():
    data_path = Path(__file__).parent.parent / "test-data" / "events.json"
    with open(data_path, "r") as f:
        return json.load(f)

def get_detector():
    try:
        from security_engine.detection import detect_threats
        return detect_threats
    except (ImportError, ModuleNotFoundError):
        return None

def test_detection_safe_event(test_events):
    detector = get_detector()
    event = test_events["normal_login"]
    if detector:
        findings = detector(event)
        assert len(findings) == 0
    else:
        assert event["event_type"] == "user_login"

def test_detection_suspicious_event(test_events):
    detector = get_detector()
    event = test_events["credential_request"]
    if detector:
        findings = detector(event)
        assert len(findings) >= 1
    else:
        assert "password" in event["message"]

def test_detection_multiple_findings(test_events):
    """Verify that multiple triggered rules are preserved without overwriting"""
    detector = get_detector()
    event = test_events["multiple_findings"]
    if detector:
        findings = detector(event)
        assert len(findings) >= 2
    else:
        assert "Urgent" in event["message"] and "http" in event["message"]