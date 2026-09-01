from utils.verdict import generate_verdict


def test_verdict_deterministic_mapping():
    assert generate_verdict(0) == "SAFE"
    assert generate_verdict(15) == "SUSPICIOUS"
    assert generate_verdict(79) == "SUSPICIOUS"
    assert generate_verdict(80) == "MALICIOUS"
    assert generate_verdict(90) == "MALICIOUS"
    assert generate_verdict(100) == "MALICIOUS"


def test_verdict_out_of_range():
    assert generate_verdict(-1) == "UNKNOWN"
    assert generate_verdict(101) == "UNKNOWN"
