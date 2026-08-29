import pytest

from engine import SecurityEngine
from exceptions import InvalidInputError


@pytest.fixture
def engine() -> SecurityEngine:
    return SecurityEngine()


def test_valid_input(engine: SecurityEngine) -> None:
    result = engine.analyze("Hello Inovix")

    assert result.status == "SAFE"
    assert result.risk_score == 0


def test_empty_input(engine: SecurityEngine) -> None:
    with pytest.raises(InvalidInputError):
        engine.analyze("")


def test_whitespace_input(engine: SecurityEngine) -> None:
    with pytest.raises(InvalidInputError):
        engine.analyze("   ")


def test_invalid_input(engine: SecurityEngine) -> None:
    with pytest.raises(InvalidInputError):
        engine.analyze(123)  # type: ignore[arg-type]


def test_safe_sample(engine: SecurityEngine) -> None:
    result = engine.analyze(
        "This is a normal message from the Inovix test environment."
    )

    assert result.status == "SAFE"
    assert result.risk_score == 0
    assert result.reasons == []
    assert result.indicators == []


def test_suspicious_sample(engine: SecurityEngine) -> None:
    result = engine.analyze(
        "Urgent action required. Please verify account immediately."
    )

    assert result.status == "MEDIUM"
    assert result.risk_score == 50
    assert "suspicious_keyword" in result.indicators


def test_url_sample(engine: SecurityEngine) -> None:
    result = engine.analyze(
        "Please review this example: https://example.com"
    )

    assert result.status == "LOW"
    assert result.risk_score == 20
    assert "url" in result.indicators