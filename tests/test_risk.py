
import pytest

from autoreconx.engine import (
    RiskLevel,
    calculate_risk_score,
)

from autoreconx.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    FindingClassification,
    Severity,
)


def make_finding(
    severity=Severity.HIGH,
    classification=FindingClassification.CONFIRMED_VULNERABILITY,
    confidence=Confidence.HIGH,
    cvss_score=None,
):
    return Finding(
        title="Test security finding",
        description="A test finding for risk calculation.",
        asset=Asset(
            host="127.0.0.1",
            port=8000,
            protocol="tcp",
            service="http",
        ),
        classification=classification,
        severity=severity,
        confidence=confidence,
        evidence=[
            Evidence(
                source="test",
                details="Test evidence.",
            )
        ],
        cvss_score=cvss_score,
    )


def test_severity_based_score():
    finding = make_finding(severity=Severity.HIGH)

    result = calculate_risk_score(finding)

    assert result.base_score == 75.0
    assert result.risk_score == 75.0
    assert result.risk_level == RiskLevel.CRITICAL


def test_cvss_score_takes_precedence_over_severity():
    finding = make_finding(
        severity=Severity.LOW,
        cvss_score=8.0,
    )

    result = calculate_risk_score(finding)

    assert result.base_score == 80.0
    assert result.risk_score == 80.0
    assert result.risk_level == RiskLevel.CRITICAL


def test_observation_has_reduced_risk():
    finding = make_finding(
        severity=Severity.HIGH,
        classification=FindingClassification.OBSERVATION,
    )

    result = calculate_risk_score(finding)

    assert result.risk_score == 7.5
    assert result.risk_level == RiskLevel.LOW


def test_potential_vulnerability_multiplier():
    finding = make_finding(
        severity=Severity.HIGH,
        classification=FindingClassification.POTENTIAL_VULNERABILITY,
    )

    result = calculate_risk_score(finding)

    assert result.risk_score == 52.5
    assert result.risk_level == RiskLevel.HIGH


def test_medium_confidence_reduces_score():
    finding = make_finding(
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )

    result = calculate_risk_score(finding)

    assert result.risk_score == 56.25


def test_low_confidence_reduces_score():
    finding = make_finding(
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
    )

    result = calculate_risk_score(finding)

    assert result.risk_score == 37.5
    assert result.risk_level == RiskLevel.MEDIUM


def test_informational_finding_has_zero_risk():
    finding = make_finding(severity=Severity.INFORMATIONAL)

    result = calculate_risk_score(finding)

    assert result.risk_score == 0.0
    assert result.risk_level == RiskLevel.LOW


def test_unknown_severity_has_zero_base_score():
    finding = make_finding(severity=Severity.UNKNOWN)

    result = calculate_risk_score(finding)

    assert result.base_score == 0.0
    assert result.risk_score == 0.0


def test_risk_assessment_contains_finding_id():
    finding = make_finding()

    result = calculate_risk_score(finding)

    assert result.finding_id == str(finding.finding_id)
    assert result.rationale


def test_invalid_input_is_rejected():
    with pytest.raises(TypeError):
        calculate_risk_score("not a finding")
