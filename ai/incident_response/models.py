"""Models for safe, policy-driven incident response."""

from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IncidentStatus(str, Enum):
    SUSPECTED = "suspected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ResponseActionType(str, Enum):
    CREATE_ALERT = "create_alert"
    WATCH_ACTOR = "watch_actor"
    RECOMMEND_RATE_LIMIT = "recommend_rate_limit"
    REQUEST_HUMAN_REVIEW = "request_human_review"


class ResponsePolicy(BaseModel):
    """Controls which response recommendations may be generated."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = "default_safe_policy"
    enabled: bool = True
    dry_run: bool = True
    minimum_severity: Literal["low", "medium", "high", "critical"] = "medium"
    allowed_actions: list[ResponseActionType] = Field(
        default_factory=lambda: [
            ResponseActionType.CREATE_ALERT,
            ResponseActionType.WATCH_ACTOR,
            ResponseActionType.RECOMMEND_RATE_LIMIT,
            ResponseActionType.REQUEST_HUMAN_REVIEW,
        ]
    )
    approval_required_actions: list[ResponseActionType] = Field(
        default_factory=lambda: [
            ResponseActionType.WATCH_ACTOR,
            ResponseActionType.RECOMMEND_RATE_LIMIT,
        ]
    )


class ResponseDecision(BaseModel):
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    policy_id: str
    action: ResponseActionType
    execution_status: Literal[
        "simulated", "approval_required", "proposed"
    ]
    approval_required: bool
    executed: bool = False
    rationale: str
    actor_type: str
    actor_reference: str
    created_at: datetime = Field(default_factory=utc_now)


class ResponsePlan(BaseModel):
    plan_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    policy_id: str
    dry_run: bool
    decisions: list[ResponseDecision] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Recommendations are based on heuristic incident evidence.",
            "No account, identity, client, or network access is changed.",
            "Dry-run decisions are simulations, not executed actions.",
            "Human approval does not itself execute an action.",
        ]
    )


class LifecycleTransition(BaseModel):
    transition_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    previous_status: IncidentStatus
    new_status: IncidentStatus
    changed_by: str
    reason: str
    timestamp: datetime = Field(default_factory=utc_now)
