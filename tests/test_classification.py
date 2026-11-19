
import pytest

from autoreconx.engine import (
    ClassificationError,
    classify_finding,
)

from autoreconx.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    FindingClassification,
    Severity,
)


@pytest.fixture
def sample_finding():
    return Finding(
        title="Open HTTP service detected",
        description="Nmap detected an open HTTP service.",
        asset=Asset(
            host="127.0.0.1",
            port=8000,
            protocol="tcp",
            service="http",
        ),
        classification=FindingClassification.OBSERVATION,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        evidence=[
            Evidence(
                source="nmap_xml",
                details="TCP port 8000 was reported open.",
            )
        ],
    )


def test_default_classification_is_observation(sample_finding):
    result = classify_finding(sample_finding)

    assert result.classification == FindingClassification.OBSERVATION


def test_potential_evidence_classifies_as_potential(sample_finding):
    evidence = Evidence(
        source="detection_rule",
        details="A detection rule identified a possible weakness.",
    )

    result = classify_finding(
        sample_finding,
        potential_evidence=evidence,
    )

    assert result.classification == (
        FindingClassification.POTENTIAL_VULNERABILITY
    )


def test_verification_evidence_classifies_as_confirmed(sample_finding):
    evidence = Evidence(
        source="verification",
        details="An authorized verification check reproduced the vulnerability.",
    )

    result = classify_finding(
        sample_finding,
        verification_evidence=evidence,
    )

    assert result.classification == (
        FindingClassification.CONFIRMED_VULNERABILITY
    )


def test_verification_takes_precedence(sample_finding):
    potential = Evidence(
        source="detection_rule",
        details="A possible weakness was identified.",
    )

    verified = Evidence(
        source="verification",
        details="The vulnerability was successfully reproduced.",
    )

    result = classify_finding(
        sample_finding,
        potential_evidence=potential,
        verification_evidence=verified,
    )

    assert result.classification == (
        FindingClassification.CONFIRMED_VULNERABILITY
    )


def test_original_finding_is_not_modified(sample_finding):
    classify_finding(
        sample_finding,
        potential_evidence=Evidence(
            source="detection_rule",
            details="Possible weakness detected.",
        ),
    )

    assert sample_finding.classification == (
        FindingClassification.OBSERVATION
    )
    assert len(sample_finding.evidence) == 1


def test_invalid_finding_is_rejected():
    with pytest.raises(ClassificationError):
        classify_finding("not a finding")


def test_invalid_potential_evidence_is_rejected(sample_finding):
    with pytest.raises(ClassificationError):
        classify_finding(
            sample_finding,
            potential_evidence="invalid evidence",
        )


def test_invalid_verification_evidence_is_rejected(sample_finding):
    with pytest.raises(ClassificationError):
        classify_finding(
            sample_finding,
            verification_evidence="invalid evidence",
        )
