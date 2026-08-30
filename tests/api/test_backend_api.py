import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200

def test_analyze_endpoint_valid():
    # FastAPI schema requires 'target' field
    payload = {
        "event_id": "EVT-TEST-01",
        "event_type": "user_login",
        "target": "User login attempt"
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code in [200, 201, 202]

def test_analyze_endpoint_invalid_payload():
    invalid_payload = {"malformed": True}
    response = client.post("/api/v1/analyze", json=invalid_payload)
    assert response.status_code in [400, 422]