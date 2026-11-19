
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from autoreconx.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    FindingClassification,
    Severity,
)


@pytest.fixture
def valid_finding_data():
    return {
        "title": "HTTP service detected",
        "description": "An HTTP service was detected on localhost.",
        "asset": {
            "host": "127.0.0.1",
            "port": 8000,
            "protocol": "tcp",
            "service": "http",
            "product": "SimpleHTTPServer",
            "version": "0.6",
        },
        "classification": FindingClassification.OBSERVATION,
        "severity": Severity.INFORMATIONAL,
        "confidence": Confidence.HIGH,
        "evidence": [
            {
                "source": "nmap_xml",
                "details": "TCP port 8000 was detected as open.",
                "artifact_path": "scans/sample.xml",
            }
        ],
    }


def test_create_valid_finding(valid_finding_data):
    finding = Finding(**valid_finding_data)

    assert finding.title == "HTTP service detected"
    assert finding.asset.host == "127.0.0.1"
    assert finding.asset.port == 8000
    assert finding.severity == Severity.INFORMATIONAL
    assert len(finding.evidence) == 1


def test_finding_generates_unique_ids(valid_finding_data):
    first = Finding(**valid_finding_data)
    second = Finding(**valid_finding_data)

    assert first.finding_id != second.finding_id


def test_finding_uses_utc_timestamp(valid_finding_data):
    finding = Finding(**valid_finding_data)

    assert finding.detected_at.tzinfo is not None
    assert finding.detected_at.utcoffset().total_seconds() == 0


def test_finding_requires_evidence(valid_finding_data):
    valid_finding_data["evidence"] = []

    with pytest.raises(ValidationError):
        Finding(**valid_finding_data)


def test_invalid_asset_port(valid_finding_data):
    valid_finding_data["asset"]["port"] = 70000

    with pytest.raises(ValidationError):
        Finding(**valid_finding_data)


def test_invalid_cvss_score(valid_finding_data):
    valid_finding_data["cvss_score"] = 10.5

    with pytest.raises(ValidationError):
        Finding(**valid_finding_data)


def test_timezone_naive_timestamp_rejected(valid_finding_data):
    valid_finding_data["detected_at"] = datetime(2026, 1, 1)

    with pytest.raises(ValidationError):
        Finding(**valid_finding_data)


def test_unknown_fields_rejected(valid_finding_data):
    valid_finding_data["unexpected_field"] = "not allowed"

    with pytest.raises(ValidationError):
        Finding(**valid_finding_data)


def test_finding_json_serialization(valid_finding_data):
    finding = Finding(**valid_finding_data)

    result = finding.model_dump(mode="json")

    assert isinstance(result["finding_id"], str)
    assert result["severity"] == "informational"
    assert result["classification"] == "observation"
    assert result["asset"]["port"] == 8000
