
import yaml

from pathlib import Path

from autoreconx.core.validator import is_authorized


def load_config(config_path="config.yaml") -> dict:
    """Load and validate the framework configuration."""

    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError("Scope configuration not found.")

    with path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict):
        raise ValueError("Configuration must contain a YAML mapping.")

    approved_scope = config.get("approved_scope")

    if not isinstance(approved_scope, dict):
        raise ValueError("approved_scope configuration is missing.")

    return config


def load_scope(config_path="config.yaml") -> list[str]:
    """Load approved hosts."""

    config = load_config(config_path)
    hosts = config["approved_scope"].get("hosts")

    if not isinstance(hosts, list) or not hosts:
        raise ValueError("Approved hosts must be a non-empty list.")

    return hosts


def load_allowed_ports(config_path="config.yaml") -> list[int]:
    """Load and validate approved TCP ports."""

    config = load_config(config_path)
    ports = config["approved_scope"].get("ports")

    if not isinstance(ports, list) or not ports:
        raise ValueError("Approved ports must be a non-empty list.")

    if any(
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        for port in ports
    ):
        raise ValueError("Approved ports must be integers between 1 and 65535.")

    if len(ports) != len(set(ports)):
        raise ValueError("Duplicate approved ports are not allowed.")

    return sorted(ports)


def check_scope(host: str) -> bool:
    """Check exact host authorization against the allowlist."""

    approved_hosts = load_scope()

    return is_authorized(host, approved_hosts)


def check_port_scope(ports: list[int]) -> bool:
    """Ensure every requested port is approved."""

    allowed_ports = load_allowed_ports()

    return set(ports).issubset(set(allowed_ports))
