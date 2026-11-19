import yaml

from pathlib import Path

from autoreconx.core.validator import is_authorized


def load_scope(config_path="config.yaml") -> list[str]:
    """
    Load approved hosts from configuration.
    """

    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError("Scope configuration not found.")

    with path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file) or {}

    hosts = config.get("approved_scope", {}).get("hosts", [])

    if not isinstance(hosts, list):
        raise ValueError("Approved hosts must be a list.")

    return hosts


def check_scope(host: str) -> bool:
    """
    Check whether a host is included in approved scope.
    """

    approved_hosts = load_scope()

    return is_authorized(host, approved_hosts)