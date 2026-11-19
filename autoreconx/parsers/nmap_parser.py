
import xml.etree.ElementTree as ET

from pathlib import Path


class NmapParserError(Exception):
    """Raised when Nmap XML parsing fails."""


def parse_nmap_xml(xml_file: str) -> dict:
    """
    Parse Nmap XML output into structured Python data.
    """

    path = Path(xml_file)

    if not path.exists():
        raise NmapParserError(
            f"Nmap XML file not found: {path}"
        )

    try:
        tree = ET.parse(path)
        root = tree.getroot()

    except ET.ParseError as error:
        raise NmapParserError(
            f"Invalid Nmap XML: {error}"
        )

    except OSError as error:
        raise NmapParserError(
            f"Unable to read Nmap XML: {error}"
        )

    if root.tag != "nmaprun":
        raise NmapParserError(
            "Invalid Nmap XML document: expected nmaprun root."
        )

    scan_info = {
        "scanner": root.get("scanner"),
        "version": root.get("version"),
        "args": root.get("args"),
        "start": root.get("start")
    }

    hosts = []

    for host_element in root.findall("host"):

        status_element = host_element.find("status")

        host_status = (
            status_element.get("state")
            if status_element is not None
            else "unknown"
        )

        addresses = []

        for address in host_element.findall("address"):
            addresses.append({
                "address": address.get("addr"),
                "type": address.get("addrtype")
            })

        hostnames = []

        hostnames_element = host_element.find("hostnames")

        if hostnames_element is not None:
            for hostname in hostnames_element.findall("hostname"):
                hostnames.append({
                    "name": hostname.get("name"),
                    "type": hostname.get("type")
                })

        ports = []

        ports_element = host_element.find("ports")

        if ports_element is not None:

            for port_element in ports_element.findall("port"):

                state_element = port_element.find("state")
                service_element = port_element.find("service")

                state = (
                    state_element.get("state")
                    if state_element is not None
                    else "unknown"
                )

                service = {}

                if service_element is not None:
                    service = {
                        "name": service_element.get("name"),
                        "product": service_element.get("product"),
                        "version": service_element.get("version"),
                        "extrainfo": service_element.get("extrainfo"),
                        "tunnel": service_element.get("tunnel")
                    }

                ports.append({
                    "port": int(port_element.get("portid")),
                    "protocol": port_element.get("protocol"),
                    "state": state,
                    "reason": (
                        state_element.get("reason")
                        if state_element is not None
                        else None
                    ),
                    "service": service
                })

        hosts.append({
            "status": host_status,
            "addresses": addresses,
            "hostnames": hostnames,
            "ports": ports
        })

    runstats_element = root.find("runstats")
    finished_element = (
        runstats_element.find("finished")
        if runstats_element is not None
        else None
    )
    hosts_element = (
        runstats_element.find("hosts")
        if runstats_element is not None
        else None
    )

    run_stats = {
        "finished": (
            finished_element.get("timestr")
            if finished_element is not None
            else None
        ),
        "hosts_up": (
            int(hosts_element.get("up", 0))
            if hosts_element is not None
            else 0
        ),
        "hosts_down": (
            int(hosts_element.get("down", 0))
            if hosts_element is not None
            else 0
        ),
        "hosts_total": (
            int(hosts_element.get("total", 0))
            if hosts_element is not None
            else 0
        )
    }

    return {
        "scan_info": scan_info,
        "hosts": hosts,
        "run_stats": run_stats
    }
