import pytest
from fastapi.testclient import TestClient

def get_app():
    try:
        from backend.main import app
        return app
    except (ImportError, ModuleNotFoundError):
        return None

app = get_app()
client = TestClient(app) if app else None

@pytest.mark.skipif(client is None, reason="Backend app not available")
def test_e2e_analyze_flow_integration():
    """End-to-End analysis execution from backend endpoint through engine analysis"""
    payload = {
        "event_id": "E2E-1001",
        "event_type": "phishing_attempt",
        "message": "Urgent wire transfer and password request"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code in [200, 201, 202]
    result = response.json()
    assert "status" in result or "risk_score" in result or "verdict" in result