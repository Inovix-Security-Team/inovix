import pytest

from exceptions import InvalidInputError
from utils.validation import validate_input


@pytest.mark.parametrize(
    "valid_input",
    [
        "Normal log message",
        "https://example.com/login",
        "192.168.1.1",
        "User login failed from IP 10.0.0.1",
    ],
)
def test_validation_valid_inputs(valid_input):
    # validate_input succeeds without returning an error.
    assert validate_input(valid_input) is None


@pytest.mark.parametrize(
    "invalid_input",
    [
        None,
        12345,
        ["invalid", "list"],
        {"invalid": "dict"},
        "",
        "   ",
    ],
)
def test_validation_invalid_inputs(invalid_input):
    with pytest.raises(InvalidInputError):
        validate_input(invalid_input)
