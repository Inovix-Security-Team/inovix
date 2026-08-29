from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Inovix API is running"
    }


def test_health_endpoint():
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok"
    }


def test_analyze_valid_request():
    response = client.post(
        "/api/v1/analyze",
        json={"target": "example.com"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"
    assert data["target"] == "example.com"
    assert data["risk_level"] == "low"
    assert data["score"] == 10
    assert "message" in data


def test_analyze_missing_target():
    response = client.post(
        "/api/v1/analyze",
        json={},
    )

    assert response.status_code == 422

    data = response.json()

    assert data["error"] == "validation_error"
    assert data["message"] == "The request data is invalid."
    assert data["details"][0]["type"] == "missing"


def test_analyze_empty_target():
    response = client.post(
        "/api/v1/analyze",
        json={"target": ""},
    )

    assert response.status_code == 422

    data = response.json()

    assert data["error"] == "validation_error"
    assert data["message"] == "The request data is invalid."
    assert data["details"][0]["type"] == "string_too_short"


def test_analyze_response_contract():
    response = client.post(
        "/api/v1/analyze",
        json={"target": "192.168.1.1"},
    )

    assert response.status_code == 200

    data = response.json()

    assert set(data.keys()) == {
        "status",
        "target",
        "risk_level",
        "score",
        "message",
    }

    assert data["status"] == "completed"
    assert data["risk_level"] in {
        "low",
        "medium",
        "high",
        "critical",
        "unknown",
    }
    assert isinstance(data["score"], int)
    assert 0 <= data["score"] <= 100
