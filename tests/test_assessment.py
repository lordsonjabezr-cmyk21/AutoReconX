
import pytest

from autoreconx.engine import (
    AssessmentEngineError,
    assess_nmap_results,
)
from autoreconx.models import (
    Confidence,
    FindingClassification,
    Severity,
)


@pytest.fixture
def sample_scan_results():
    return {
        "scan_info": {
            "scanner": "nmap",
            "version": "7.99",
        },
        "hosts": [
            {
                "status": "up",
                "addresses": [
                    {
                        "address": "127.0.0.1",
                        "type": "ipv4",
                    }
                ],
                "ports": [
                    {
                        "port": 8000,
                        "protocol": "tcp",
                        "state": "open",
                        "reason": "syn-ack",
                        "service": {
                            "name": "http",
                            "product": "SimpleHTTPServer",
                            "version": "0.6",
                        },
                    },
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "state": "closed",
                        "reason": "conn-refused",
                        "service": {
                            "name": "http-proxy",
                            "product": None,
                            "version": None,
                        },
                    },
                ],
            }
        ],
        "run_stats": {
            "hosts_up": 1,
            "hosts_down": 0,
            "hosts_total": 1,
        },
    }


def test_open_port_generates_finding(sample_scan_results):
    findings = assess_nmap_results(sample_scan_results)

    assert len(findings) == 1
    assert findings[0].asset.port == 8000


def test_closed_port_does_not_generate_finding(sample_scan_results):
    findings = assess_nmap_results(sample_scan_results)

    assert all(finding.asset.port != 8080 for finding in findings)


def test_finding_classification(sample_scan_results):
    findings = assess_nmap_results(sample_scan_results)

    assert findings[0].classification == FindingClassification.OBSERVATION
    assert findings[0].severity == Severity.INFORMATIONAL
    assert findings[0].confidence == Confidence.HIGH


def test_asset_service_information(sample_scan_results):
    findings = assess_nmap_results(sample_scan_results)

    asset = findings[0].asset

    assert asset.host == "127.0.0.1"
    assert asset.port == 8000
    assert asset.protocol == "tcp"
    assert asset.service == "http"
    assert asset.product == "SimpleHTTPServer"
    assert asset.version == "0.6"


def test_nmap_evidence_is_attached(sample_scan_results):
    findings = assess_nmap_results(sample_scan_results)

    evidence = findings[0].evidence[0]

    assert evidence.source == "nmap_xml"
    assert "port 8000" in evidence.details
    assert "open" in evidence.details


def test_artifact_path_is_preserved(sample_scan_results):
    findings = assess_nmap_results(
        sample_scan_results,
        artifact_path="scans/sample.xml",
    )

    assert findings[0].evidence[0].artifact_path == "scans/sample.xml"


def test_down_host_is_ignored(sample_scan_results):
    sample_scan_results["hosts"][0]["status"] = "down"

    findings = assess_nmap_results(sample_scan_results)

    assert findings == []


def test_empty_hosts_returns_empty_findings():
    findings = assess_nmap_results({"hosts": []})

    assert findings == []


def test_invalid_scan_input_is_rejected():
    with pytest.raises(AssessmentEngineError):
        assess_nmap_results("invalid input")


def test_active_host_without_address_is_rejected():
    results = {
        "hosts": [
            {
                "status": "up",
                "addresses": [],
                "ports": [],
            }
        ]
    }

    with pytest.raises(AssessmentEngineError):
        assess_nmap_results(results)
