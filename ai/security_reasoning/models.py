from typing import Literal

from pydantic import BaseModel, Field


ReasoningCategory = Literal[
    "bola_review",
    "bfla_review",
    "sensitive_data_review",
    "destructive_operation_review",
    "documented_vulnerability_reference",
    "mutation_without_read_review",
    "delete_without_read_review",
    "multiple_mutation_types_review",
    "shap_dominant_feature",
    "shap_risk_increasing_feature",
    "shap_risk_decreasing_feature",
]

ReasoningSeverity = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]

ReasoningConfidence = Literal["low", "medium", "high"]

ValidationStatus = Literal[
    "not_validated",
    "documented_reference",
]

EvidenceSourceType = Literal[
    "api_structure",
    "security_graph",
    "ml_prediction",
    "shap",
    "documented_catalog",
    "runtime_validation",
]

EvidenceScope = Literal[
    "endpoint",
    "assessment_graph",
    "model_endpoint",
    "documented_catalog",
]

EvidenceRelationshipType = Literal[
    "supports",
    "overlaps",
    "conflicts",
    "explains",
    "documented_match",
]


class ReasoningEvidence(BaseModel):
    """
    A traceable item supporting a security reasoning finding.

    Evidence describes its source and observation. It does not
    automatically establish that a vulnerability exists.
    """

    source: str
    detail: str
    reference: str | None = None


class SecurityReasoningFinding(BaseModel):
    """
    One human-readable security concern produced by the reasoning engine.
    """

    finding_id: str
    category: ReasoningCategory
    title: str
    severity: ReasoningSeverity
    confidence: ReasoningConfidence
    validation_status: ValidationStatus = "not_validated"
    explanation: str
    evidence: list[ReasoningEvidence] = Field(default_factory=list)
    recommended_validation: list[str] = Field(default_factory=list)


class SecurityReasoningResult(BaseModel):
    """
    Combined human-readable reasoning for one API endpoint.
    """

    path: str
    method: str
    overall_assessment: Literal[
        "no_review_signal",
        "review_recommended",
        "documented_reference_match",
    ]
    summary: str
    findings: list[SecurityReasoningFinding] = Field(default_factory=list)
    vulnerabilities_confirmed: bool = False
    limitations: list[str] = Field(default_factory=list)


class EvidenceSource(BaseModel):
    """
    Normalized evidence signal used by the correlation engine.

    dependency_group identifies signals derived from the same
    underlying system. For example, ML prediction and SHAP output
    should both use the same model dependency group.
    """

    source_id: str
    source_type: EvidenceSourceType
    scope: EvidenceScope
    detail: str
    reference: str | None = None
    indicator: str | None = None
    direction: Literal["positive", "negative", "neutral"] | None = None
    dependency_group: str | None = None


class EvidenceRelationship(BaseModel):
    """
    Describes the relationship between two normalized evidence signals.
    """

    source_id_a: str
    source_id_b: str
    relationship: EvidenceRelationshipType
    rationale: str
    independent_sources: bool = True


class CorrelatedEvidenceGroup(BaseModel):
    """
    Evidence grouped by the same scope and reference.

    independent_source_count is descriptive only. It must not be
    interpreted as a vulnerability confidence score.
    """

    group_id: str
    scope: EvidenceScope
    reference: str | None = None
    evidence: list[EvidenceSource] = Field(default_factory=list)
    relationships: list[EvidenceRelationship] = Field(default_factory=list)
    independent_source_count: int = 0


class EvidenceCorrelationResult(BaseModel):
    """
    Complete output of the standalone evidence correlation engine.
    """

    groups: list[CorrelatedEvidenceGroup] = Field(default_factory=list)
    relationships: list[EvidenceRelationship] = Field(default_factory=list)
    total_evidence_sources: int = 0
    total_relationships: int = 0
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Correlation identifies relationships between signals; it does not confirm vulnerabilities.",
            "Signals derived from the same dependency group are not independent evidence.",
            "Evidence with different scopes or references is not merged into the same group.",
            "The number of independent sources is descriptive and is not a confidence score.",
        ]
    )
