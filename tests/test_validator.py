import pytest

from autoreconx.core.validator import (
    validate_target,
    is_authorized
)


def test_valid_domain():
    result = validate_target("example.com")

    assert result["host"] == "example.com"
    assert result["type"] == "DOMAIN"


def test_valid_ipv4():
    result = validate_target("192.168.1.10")

    assert result["type"] == "IP"


def test_valid_url():
    result = validate_target("https://example.com")

    assert result["scheme"] == "https"


def test_invalid_target():
    with pytest.raises(ValueError):
        validate_target("invalid target!!!")


def test_authorized_target():
    assert is_authorized(
        "example.com",
        ["example.com"]
    )


def test_unauthorized_target():
    assert not is_authorized(
        "attacker.com",
        ["example.com"]
    )