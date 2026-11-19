
from enum import Enum
from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import field_validator

class FindingClassification(str, Enum):
    OBSERVATION = "observation"
    POTENTIAL_VULNERABILITY = "potential_vulnerability"
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Asset(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    host: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None


class Evidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    source: str = Field(min_length=1, max_length=80)
    details: str = Field(min_length=1, max_length=2000)
    artifact_path: str | None = None


class Finding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    finding_id: UUID = Field(default_factory=uuid4)

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)

    asset: Asset

    classification: FindingClassification
    severity: Severity
    confidence: Confidence

    evidence: list[Evidence] = Field(min_length=1)

    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
    )

    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("detected_at")
    @classmethod
    def validate_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("detected_at must be timezone-aware")
        return value

