
from autoreconx.parsers.nmap_parser import parse_nmap_xml
from autoreconx.engine import assess_nmap_results
from autoreconx.models import (
    FindingClassification,
    Severity,
)


def test_nmap_xml_to_assessment_finding(tmp_path):
    xml_content = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99">
    <host>
        <status state="up" reason="localhost-response"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <ports>
            <port protocol="tcp" portid="8000">
                <state state="open" reason="syn-ack"/>
                <service
                    name="http"
                    product="SimpleHTTPServer"
                    version="0.6"
                />
            </port>
        </ports>
    </host>
    <runstats>
        <finished timestr="test scan"/>
        <hosts up="1" down="0" total="1"/>
    </runstats>
</nmaprun>
"""

    xml_file = tmp_path / "nmap_test.xml"
    xml_file.write_text(xml_content, encoding="utf-8")

    parsed_results = parse_nmap_xml(str(xml_file))

    findings = assess_nmap_results(
        parsed_results,
        artifact_path=str(xml_file),
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.asset.host == "127.0.0.1"
    assert finding.asset.port == 8000
    assert finding.asset.service == "http"
    assert finding.asset.product == "SimpleHTTPServer"

    assert finding.classification == FindingClassification.OBSERVATION
    assert finding.severity == Severity.INFORMATIONAL

    assert finding.evidence[0].source == "nmap_xml"
    assert finding.evidence[0].artifact_path == str(xml_file)
