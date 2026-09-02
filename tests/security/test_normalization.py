from utils.normalization import normalize_input


def test_normalization_structure():
    normalized = normalize_input(
        "  suspicious login attempt  ",
        source="  test-source  ",
        event_type="  user_login  ",
        metadata={"ip": "192.168.1.1"},
    )

    assert normalized.content == "suspicious login attempt"
    assert normalized.source == "test-source"
    assert normalized.event_type == "user_login"
    assert normalized.metadata == {"ip": "192.168.1.1"}
