
from typing import Any

from autoreconx.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    FindingClassification,
    Severity,
)


class AssessmentEngineError(Exception):
    """Raised when assessment input cannot be processed."""


def _get_host_address(host_data: dict[str, Any]) -> str:
    """Select the best available address for an Nmap host."""

    addresses = host_data.get("addresses", [])

    if not isinstance(addresses, list) or not addresses:
        raise AssessmentEngineError(
            "An active host must contain at least one IP address."
        )

    # Prefer IPv4, then use the first available address.
    for address in addresses:
        if address.get("type") == "ipv4":
            return address["address"]

    return addresses[0]["address"]


def assess_nmap_results(
    scan_results: dict[str, Any],
    artifact_path: str | None = None,
) -> list[Finding]:
    """
    Convert parsed Nmap results into structured observations.

    Only open ports on hosts reported as up generate findings.
    """

    if not isinstance(scan_results, dict):
        raise AssessmentEngineError(
            "Nmap scan results must be a dictionary."
        )

    hosts = scan_results.get("hosts")

    if not isinstance(hosts, list):
        raise AssessmentEngineError(
            "Nmap scan results must contain a hosts list."
        )

    findings: list[Finding] = []

    for host_data in hosts:

        if not isinstance(host_data, dict):
            raise AssessmentEngineError(
                "Each host entry must be a dictionary."
            )

        # Ignore hosts that Nmap did not identify as active.
        if host_data.get("status") != "up":
            continue

        host_address = _get_host_address(host_data)
        ports = host_data.get("ports", [])

        if not isinstance(ports, list):
            raise AssessmentEngineError(
                "Host ports must be represented as a list."
            )

        for port_data in ports:

            if not isinstance(port_data, dict):
                raise AssessmentEngineError(
                    "Each port entry must be a dictionary."
                )

            # Closed and filtered ports do not generate observations
            # in this initial assessment profile.
            if port_data.get("state") != "open":
                continue

            service = port_data.get("service") or {}

            if not isinstance(service, dict):
                raise AssessmentEngineError(
                    "Port service information must be a dictionary."
                )

            port_number = port_data.get("port")
            protocol = port_data.get("protocol")

            service_name = service.get("name") or "unknown"
            product = service.get("product")
            version = service.get("version")

            asset = Asset(
                host=host_address,
                port=port_number,
                protocol=protocol,
                service=service_name,
                product=product,
                version=version,
            )

            title = (
                f"Open {service_name} service detected "
                f"on port {port_number}"
            )

            description = (
                f"Nmap identified an open {protocol} port "
                f"{port_number} on {host_address}. "
                f"The detected service is {service_name}."
            )

            if product:
                description += f" Product: {product}."

            if version:
                description += f" Version: {version}."

            evidence_details = (
                f"Nmap reported {protocol} port {port_number} "
                f"as open. Service: {service_name}."
            )

            if product:
                evidence_details += f" Product: {product}."

            if version:
                evidence_details += f" Version: {version}."

            if port_data.get("reason"):
                evidence_details += (
                    f" State reason: {port_data['reason']}."
                )

            evidence = Evidence(
                source="nmap_xml",
                details=evidence_details,
                artifact_path=artifact_path,
            )

            finding = Finding(
                title=title,
                description=description,
                asset=asset,
                classification=FindingClassification.OBSERVATION,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                evidence=[evidence],
                tags=["nmap", "network", "service-discovery"],
            )

            findings.append(finding)

    return findings
