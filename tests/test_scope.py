
import pytest

from autoreconx.core.scope import (
    load_allowed_ports,
    check_port_scope,
)


def test_load_approved_ports():
    assert load_allowed_ports() == [3000, 8000, 8080, 9000]


def test_approved_ports():
    assert check_port_scope([3000, 8080])


def test_unapproved_port():
    assert not check_port_scope([22])


def test_mixed_approved_and_unapproved_ports():
    assert not check_port_scope([3000, 22])


def test_duplicate_ports_in_config(tmp_path):
    config = tmp_path / "config.yaml"

    config.write_text(
        """approved_scope:
  hosts:
    - "127.0.0.1"
  ports:
    - 3000
    - 3000
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_allowed_ports(str(config))


def test_invalid_port_in_config(tmp_path):
    config = tmp_path / "config.yaml"

    config.write_text(
        """approved_scope:
  hosts:
    - "127.0.0.1"
  ports:
    - 70000
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_allowed_ports(str(config))
