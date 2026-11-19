
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from autoreconx.models import (
    Confidence,
    Finding,
    FindingClassification,
    Severity,
)


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment(BaseModel):
    """Calculated risk priority for a finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    base_score: float = Field(ge=0.0, le=100.0)
    classification_multiplier: float
    confidence_multiplier: float
    rationale: str


SEVERITY_SCORES = {
    Severity.INFORMATIONAL: 0.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 100.0,
    Severity.UNKNOWN: 0.0,
}

CLASSIFICATION_MULTIPLIERS = {
    FindingClassification.OBSERVATION: 0.10,
    FindingClassification.POTENTIAL_VULNERABILITY: 0.70,
    FindingClassification.CONFIRMED_VULNERABILITY: 1.0,
}

CONFIDENCE_MULTIPLIERS = {
    Confidence.LOW: 0.50,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}


def _get_risk_level(score: float) -> RiskLevel:
    """Convert a numeric risk score into a risk band."""

    if score >= 70:
        return RiskLevel.CRITICAL

    if score >= 40:
        return RiskLevel.HIGH

    if score >= 20:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def calculate_risk_score(finding: Finding) -> RiskAssessment:
    """
    Calculate a risk priority score for a finding.

    CVSS is used as the base score when available.
    Otherwise, the finding's severity mapping is used.
    """

    if not isinstance(finding, Finding):
        raise TypeError("Input must be a valid Finding instance.")

    if finding.cvss_score is not None:
        base_score = finding.cvss_score * 10
    else:
        base_score = SEVERITY_SCORES[finding.severity]

    classification_multiplier = (
        CLASSIFICATION_MULTIPLIERS[finding.classification]
    )

    confidence_multiplier = (
        CONFIDENCE_MULTIPLIERS[finding.confidence]
    )

    risk_score = round(
        base_score
        * classification_multiplier
        * confidence_multiplier,
        2,
    )

    risk_level = _get_risk_level(risk_score)

    rationale = (
        f"Base score: {base_score}; "
        f"classification multiplier: {classification_multiplier}; "
        f"confidence multiplier: {confidence_multiplier}; "
        f"final risk score: {risk_score}."
    )

    return RiskAssessment(
        finding_id=str(finding.finding_id),
        risk_score=risk_score,
        risk_level=risk_level,
        base_score=base_score,
        classification_multiplier=classification_multiplier,
        confidence_multiplier=confidence_multiplier,
        rationale=rationale,
    )
