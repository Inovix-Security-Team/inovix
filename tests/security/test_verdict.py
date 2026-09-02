import pytest

from utils.verdict import generate_verdict


@pytest.mark.parametrize(
    "risk_score, expected_verdict",
    [
        (0, "SAFE"),
        (1, "SUSPICIOUS"),
        (29, "SUSPICIOUS"),
        (30, "SUSPICIOUS"),
        (59, "SUSPICIOUS"),
        (60, "SUSPICIOUS"),
        (79, "SUSPICIOUS"),
        (80, "MALICIOUS"),
        (100, "MALICIOUS"),
    ],
)
def test_verdict_deterministic_mapping(
    risk_score,
    expected_verdict,
):
    assert generate_verdict(risk_score) == expected_verdict


@pytest.mark.parametrize(
    "risk_score",
    [-1, 101, 150],
)
def test_verdict_out_of_range(risk_score):
    assert generate_verdict(risk_score) == "UNKNOWN"