
import shutil
import subprocess

from datetime import datetime, timezone
from pathlib import Path


class NmapScannerError(Exception):
    """Raised when Nmap scanning fails."""


def find_nmap() -> str:
    """
    Locate the Nmap executable.
    """

    executable = shutil.which("nmap")

    if executable is None:
        raise NmapScannerError(
            "Nmap executable not found. Install Nmap and add it to PATH."
        )

    return executable


def validate_ports(ports: list[int]) -> list[int]:
    """
    Validate the requested TCP ports.
    """

    if not ports:
        raise ValueError("At least one port must be specified.")

    if len(ports) != len(set(ports)):
        raise ValueError("Duplicate ports are not allowed.")

    for port in ports:
        if not isinstance(port, int) or isinstance(port, bool):
            raise ValueError("Ports must be integers.")

        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port: {port}")

    return sorted(ports)


def run_nmap(
    target: str,
    ports: list[int],
    output_dir: str = "scans",
    timeout: int = 180
) -> dict:
    """
    Execute a restricted Nmap TCP connect scan.

    The caller must validate target authorization and scope
    before invoking this function.
    """

    executable = find_nmap()

    validated_ports = validate_ports(ports)

    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ValueError("Timeout must be an integer.")

    if not 1 <= timeout <= 600:
        raise ValueError("Timeout must be between 1 and 600 seconds.")

    scan_directory = Path(output_dir)
    scan_directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S"
    )

    safe_target = "".join(
        character if character.isalnum() or character in ".-_" else "_"
        for character in target
    )

    output_file = scan_directory / f"nmap_{safe_target}_{timestamp}.xml"

    command = [
        executable,
        "-sT",
        "-sV",
        "-T3",
        "-p",
        ",".join(map(str, validated_ports)),
        "-oX",
        str(output_file),
        target
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

    except subprocess.TimeoutExpired:
        raise NmapScannerError(
            f"Nmap scan exceeded timeout of {timeout} seconds."
        )

    except OSError as error:
        raise NmapScannerError(
            f"Unable to execute Nmap: {error}"
        )

    if result.returncode != 0:
        raise NmapScannerError(
            f"Nmap exited with code {result.returncode}: "
            f"{result.stderr.strip()}"
        )

    if not output_file.exists() or output_file.stat().st_size == 0:
        raise NmapScannerError(
            "Nmap completed without producing XML output."
        )

    return {
        "target": target,
        "ports": validated_ports,
        "return_code": result.returncode,
        "xml_file": str(output_file),
        "stdout": result.stdout,
        "stderr": result.stderr
    }
