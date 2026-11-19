
import pytest

from autoreconx.parsers.nmap_parser import (
    parse_nmap_xml,
    NmapParserError
)


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99" args="nmap -sT">
    <host>
        <status state="up" reason="localhost-response"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="localhost" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="8080">
                <state state="open" reason="syn-ack"/>
                <service
                    name="http"
                    product="Apache httpd"
                    version="2.4.58"/>
            </port>
            <port protocol="tcp" portid="9000">
                <state state="closed" reason="conn-refused"/>
                <service name="unknown"/>
            </port>
        </ports>
    </host>
    <runstats>
        <finished timestr="2026-11-19 10:00:00"/>
        <hosts up="1" down="0" total="1"/>
    </runstats>
</nmaprun>
"""


def create_xml_file(tmp_path, content):
    xml_file = tmp_path / "sample.xml"
    xml_file.write_text(content, encoding="utf-8")
    return str(xml_file)


def test_parse_host_address(tmp_path):
    xml_file = create_xml_file(tmp_path, SAMPLE_XML)

    result = parse_nmap_xml(xml_file)

    assert result["hosts"][0]["addresses"][0]["address"] == "127.0.0.1"


def test_parse_open_port(tmp_path):
    xml_file = create_xml_file(tmp_path, SAMPLE_XML)

    result = parse_nmap_xml(xml_file)

    port = result["hosts"][0]["ports"][0]

    assert port["port"] == 8080
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"


def test_parse_service_information(tmp_path):
    xml_file = create_xml_file(tmp_path, SAMPLE_XML)

    result = parse_nmap_xml(xml_file)

    service = result["hosts"][0]["ports"][0]["service"]

    assert service["name"] == "http"
    assert service["product"] == "Apache httpd"
    assert service["version"] == "2.4.58"


def test_parse_closed_port(tmp_path):
    xml_file = create_xml_file(tmp_path, SAMPLE_XML)

    result = parse_nmap_xml(xml_file)

    port = result["hosts"][0]["ports"][1]

    assert port["port"] == 9000
    assert port["state"] == "closed"


def test_parse_scan_statistics(tmp_path):
    xml_file = create_xml_file(tmp_path, SAMPLE_XML)

    result = parse_nmap_xml(xml_file)

    assert result["run_stats"]["hosts_up"] == 1
    assert result["run_stats"]["hosts_down"] == 0
    assert result["run_stats"]["hosts_total"] == 1


def test_missing_xml_file(tmp_path):
    with pytest.raises(NmapParserError):
        parse_nmap_xml(str(tmp_path / "missing.xml"))


def test_malformed_xml(tmp_path):
    xml_file = create_xml_file(
        tmp_path,
        "<nmaprun><host>"
    )

    with pytest.raises(NmapParserError):
        parse_nmap_xml(xml_file)


def test_wrong_xml_root(tmp_path):
    xml_file = create_xml_file(
        tmp_path,
        "<invalid></invalid>"
    )

    with pytest.raises(NmapParserError):
        parse_nmap_xml(xml_file)
