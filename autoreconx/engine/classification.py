
from autoreconx.models import Evidence, Finding, FindingClassification


class ClassificationError(Exception):
    """Raised when finding classification cannot be completed."""


def classify_finding(
    finding: Finding,
    potential_evidence: Evidence | None = None,
    verification_evidence: Evidence | None = None,
) -> Finding:
    """
    Classify a finding based on explicitly supplied evidence.

    Rules:
    - Verification evidence supplied: CONFIRMED_VULNERABILITY
    - Potential vulnerability evidence supplied: POTENTIAL_VULNERABILITY
    - Neither supplied: OBSERVATION

    The caller must supply verification evidence only after
    an appropriate verification process has succeeded.
    """

    if not isinstance(finding, Finding):
        raise ClassificationError(
            "Input must be a valid Finding instance."
        )

    if potential_evidence is not None and not isinstance(
        potential_evidence, Evidence
    ):
        raise ClassificationError(
            "Potential evidence must be an Evidence instance."
        )

    if verification_evidence is not None and not isinstance(
        verification_evidence, Evidence
    ):
        raise ClassificationError(
            "Verification evidence must be an Evidence instance."
        )

    updated_evidence = list(finding.evidence)

    if potential_evidence is not None:
        updated_evidence.append(potential_evidence)

    if verification_evidence is not None:
        updated_evidence.append(verification_evidence)
        classification = FindingClassification.CONFIRMED_VULNERABILITY

    elif potential_evidence is not None:
        classification = FindingClassification.POTENTIAL_VULNERABILITY

    else:
        classification = FindingClassification.OBSERVATION

    finding_data = finding.model_dump()
    finding_data["classification"] = classification
    finding_data["evidence"] = updated_evidence

    return Finding.model_validate(finding_data)
