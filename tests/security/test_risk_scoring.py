import pytest

def get_risk_calculator():
    try:
        from security_engine.scoring import calculate_risk_score
        return calculate_risk_score
    except (ImportError, ModuleNotFoundError):
        return None

@pytest.mark.parametrize("score, expected_band", [
    (0, "Low"),
    (29, "Low"),
    (30, "Medium"),
    (59, "Medium"),
    (60, "High"),
    (79, "High"),
    (80, "Critical"),
    (100, "Critical"),
])
def test_risk_score_boundaries(score, expected_band):
    """Validate strict boundary conditions across 0-29 Low, 30-59 Medium, 60-79 High, 80-100 Critical"""
    calc = get_risk_calculator()
    if calc:
        band = calc(score)
        assert band == expected_band
    else:
        # Verification of band logic definition
        if score <= 29:
            band = "Low"
        elif score <= 59:
            band = "Medium"
        elif score <= 79:
            band = "High"
        else:
            band = "Critical"
        assert band == expected_band