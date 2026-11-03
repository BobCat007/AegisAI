from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


KnowledgeDocumentType = Literal[
    "reasoning_finding",
    "evidence_source",
    "remediation",
    "authorization_finding",
    "behavioral_anomaly",
    "attack_chain",
]


class KnowledgeDocument(BaseModel):
    """A sanitized, traceable record derived from an existing assessment."""

    model_config = ConfigDict(extra="forbid")

    document_id: str = Field(min_length=1)
    document_type: KnowledgeDocumentType
    title: str = Field(min_length=1)
    content: str = Field(min_length=1)
    source: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    severity: str | None = None
    priority: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    validation_status: str | None = None
    confirmed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
