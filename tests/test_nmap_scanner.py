
import pytest

from autoreconx.scanners.nmap_scanner import (
    find_nmap,
    validate_ports,
    NmapScannerError
)


def test_nmap_is_available():
    executable = find_nmap()
    assert executable.lower().endswith("nmap.exe")


def test_valid_ports():
    assert validate_ports([8080, 3000]) == [3000, 8080]


def test_empty_ports():
    with pytest.raises(ValueError):
        validate_ports([])


def test_invalid_port():
    with pytest.raises(ValueError):
        validate_ports([70000])


def test_duplicate_ports():
    with pytest.raises(ValueError):
        validate_ports([8080, 8080])


def test_boolean_port_rejected():
    with pytest.raises(ValueError):
        validate_ports([True])
