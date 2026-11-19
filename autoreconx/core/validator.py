import ipaddress
import re
from urllib.parse import urlsplit


def validate_target(target: str) -> dict:
    """
    Validate an IP address, domain, or HTTP/HTTPS URL.
    """

    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    if any(char.isspace() for char in target):
        raise ValueError("Target cannot contain whitespace.")

    scheme = None
    port = None

    # Handle raw IP addresses first.
    try:
        address = ipaddress.ip_address(target)

        return {
            "host": str(address),
            "type": "IP",
            "scheme": None,
            "port": None
        }

    except ValueError:
        pass

    # Parse URLs or bare hostnames.
    parsed = urlsplit(
        target if "://" in target else f"//{target}"
    )

    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS are supported.")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not allowed.")

    if parsed.query or parsed.fragment:
        raise ValueError("Query strings and fragments are not supported.")

    host = parsed.hostname

    if not host:
        raise ValueError("Invalid hostname.")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid port number.")

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    try:
        address = ipaddress.ip_address(host)
        host = str(address)
        target_type = "IP"

    except ValueError:
        try:
            host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("Invalid domain name.")

        if len(host) > 253:
            raise ValueError("Domain name is too long.")

        labels = host.split(".")

        label_pattern = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )

        if not all(label_pattern.fullmatch(label) for label in labels):
            raise ValueError("Invalid domain name.")

        if any(len(label) > 63 for label in labels):
            raise ValueError("Domain label is too long.")

        target_type = "DOMAIN"

    scheme = parsed.scheme or None

    return {
        "host": host,
        "type": target_type,
        "scheme": scheme,
        "port": port
    }


def is_authorized(host: str, approved_scope: list[str]) -> bool:
    """
    Check whether the target exactly matches approved scope.
    """

    normalized_scope = set()

    for item in approved_scope:
        normalized_scope.add(validate_target(item)["host"])

    return host in normalized_scope