from pydantic import BaseModel, Field


class SecurityEvidence(BaseModel):
    """
    Independently sourced security evidence tied to an API operation.

    This model is intentionally separate from AegisAI's predicted risk
    assessment so evaluation does not become circular.
    """

    source: str
    vulnerability_type: str
    path: str
    method: str
    description: str
    confidence: str = "documented"
    references: list[str] = Field(default_factory=list)


CRAPI_SECURITY_EVIDENCE = [
    SecurityEvidence(
        source="OWASP crAPI",
        vulnerability_type="BFLA",
        path="/identity/api/v2/admin/videos/{video_id}",
        method="DELETE",
        description=(
            "Documented broken function-level authorization involving "
            "administrative deletion of another user's profile video."
        ),
        confidence="documented",
        references=["OWASP crAPI", "OWASP API Security Testing Framework"],
    ),
    SecurityEvidence(
        source="OWASP crAPI",
        vulnerability_type="BOLA",
        path="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        description=(
            "Documented broken object-level authorization involving "
            "access to another user's vehicle information."
        ),
        confidence="documented",
        references=["OWASP crAPI"],
    ),
]
