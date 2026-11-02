from typing import Literal

from pydantic import BaseModel, Field


AuthorizationFindingStatus = Literal[
    "consistent",
    "inconsistent",
]


class AuthorizationFinding(BaseModel):
    """
    Legacy authorization consistency finding.
    """

    identity: str
    expected_outcome: Literal["allow", "deny"]
    observed_status_code: int
    status: AuthorizationFindingStatus


SecurityFindingType = Literal["bola", "bfla"]

SecurityFindingStatus = Literal[
    "confirmed",
    "suspected",
    "not_detected",
    "inconclusive",
]

SecurityFindingSeverity = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "informational",
]


class AuthorizationSecurityFinding(BaseModel):
    """
    Evidence-backed BOLA or BFLA analysis result.

    A confirmed result requires the evidence conditions documented by
    the corresponding analyzer. It is not a substitute for manual review.
    """

    finding_type: SecurityFindingType
    status: SecurityFindingStatus
    severity: SecurityFindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)

    title: str
    description: str

    identity: str | None = None
    resource_id: str | None = None
    operation: str

    evidence: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict
    )
