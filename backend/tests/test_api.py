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


def test_analyze_response_contract():
    response = client.post(
        "/api/v1/analyze",
        json={
            "target": "192.168.1.1"
        },
    )

    assert response.status_code == 200

    data = response.json()

    expected_keys = {
        "status",
        "target",
        "risk_score",
        "verdict",
        "findings",
        "reasons",
        "indicators",
        "impact",
        "response",
        "verification",
    }

    assert set(data.keys()) == expected_keys

    # API execution status must remain "completed".
    assert data["status"] == "completed"
    assert isinstance(data["status"], str)

    # SecurityEngine result is exposed separately.
    assert isinstance(data["target"], str)

    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100

    assert isinstance(data["verdict"], str)
    assert isinstance(data["findings"], list)
    assert isinstance(data["reasons"], list)
    assert isinstance(data["indicators"], list)


def test_analyze_credential_request():
    response = client.post(
        "/api/v1/analyze",
        json={
            "target": "Please send your password and OTP."
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"
    assert data["risk_score"] == 80
    assert data["verdict"] == "MALICIOUS"

    rule_ids = {
        finding["rule_id"]
        for finding in data["findings"]
    }

    assert "CREDENTIAL_REQUEST" in rule_ids


def test_analyze_multiple_findings():
    response = client.post(
        "/api/v1/analyze",
        json={
            "target": (
                "Urgent action required. Send your password and "
                "bank transfer details to https://example.com."
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"
    assert data["risk_score"] <= 100
    assert data["verdict"] in {
        "SUSPICIOUS",
        "MALICIOUS",
    }

    rule_ids = {
        finding["rule_id"]
        for finding in data["findings"]
    }

    assert "SUSPICIOUS_LANGUAGE" in rule_ids
    assert "URL_PRESENT" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids
    assert "FINANCIAL_REQUEST" in rule_ids


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
        json={
            "target": ""
        },
    )

    assert response.status_code == 422

    data = response.json()

    assert data["error"] == "validation_error"
    assert data["message"] == "The request data is invalid."
    assert data["details"][0]["type"] == "string_too_short"


def test_analyze_whitespace_target():
    response = client.post(
        "/api/v1/analyze",
        json={
            "target": "   "
        },
    )

    assert response.status_code == 422


def test_analyze_null_target():
    response = client.post(
        "/api/v1/analyze",
        json={
            "target": None
        },
    )

    assert response.status_code == 422


def test_analyze_incorrect_target_type():
    response = client.post(
        "/api/v1/analyze",
        json={
            "target": 12345
        },
    )

    assert response.status_code == 422
