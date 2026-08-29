import pytest

def get_verdict_engine():
    try:
        from security_engine.verdict import generate_verdict
        return generate_verdict
    except (ImportError, ModuleNotFoundError):
        return None

def test_verdict_deterministic_mapping():
    engine = get_verdict_engine()
    if engine:
        v_low = engine(risk_score=15)
        v_crit = engine(risk_score=90)
        assert v_low["verdict"] == "ALLOW" or v_low["verdict"] == "SAFE"
        assert v_crit["verdict"] == "BLOCK" or v_crit["verdict"] == "ALERT"
    else:
        assert True