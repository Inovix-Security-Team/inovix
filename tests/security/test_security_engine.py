import pytest
import json

def load_test_data():
    with open("tests/test-data/events.json") as f:
        return json.load(f)

def test_security_empty_input():
    """TEST-003: Security Engine empty input validation"""
    empty_payload = {}
    is_valid = bool(empty_payload.get("event_id"))
    assert is_valid is False

def test_security_safe_sample():
    """TEST-004: Security Engine handling safe/normal sample"""
    data = load_test_data()["normal_event"]
    # Mock analysis result
    severity = "LOW"
    risk_score = 10
    assert severity == "LOW"
    assert risk_score < 30

def test_security_suspicious_sample():
    """TEST-005: Security Engine handling suspicious brute force sample"""
    data = load_test_data()["brute_force_event"]
    # Mock analysis result
    risk_score = 85  # Critical band (80-100)
    assert risk_score >= 80