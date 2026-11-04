from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class IncidentEvidence(BaseModel):
    event_id: str
    timestamp: datetime
    method: str
    endpoint_path: str
    status_code: int
    indicators: list[str] = Field(default_factory=list)


class SecurityIncident(BaseModel):
    incident_id: str
    actor_type: Literal["identity", "client"]
    actor_reference: str
    severity: Literal["low", "medium", "high", "critical"]
    priority_score: int = Field(ge=0, le=100)
    status: Literal["suspected"] = "suspected"
    window_start: datetime
    window_end: datetime
    event_count: int
    distinct_endpoints: int
    indicators: list[str]
    evidence: list[IncidentEvidence]
    summary: str
    vulnerabilities_confirmed: bool = False
    limitations: list[str] = Field(default_factory=lambda: [
        "Incidents are heuristic correlations of telemetry metadata.",
        "HTTP status patterns do not prove malicious intent.",
        "Pseudonymous identifiers may be shared or incomplete.",
        "A suspected incident is not a confirmed vulnerability.",
    ])


class IncidentCorrelationResult(BaseModel):
    incidents: list[SecurityIncident] = Field(default_factory=list)
    events_considered: int = 0
    correlation_window_seconds: int
    limitations: list[str] = Field(default_factory=lambda: [
        "Correlation uses fixed time windows.",
        "Events without pseudonymous identity or client hashes "
        "cannot be actor-correlated.",
        "Only retained telemetry events are considered.",
    ])
