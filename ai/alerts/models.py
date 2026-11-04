"""Persistent analyst-facing alert models."""

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now():
    return datetime.now(timezone.utc)


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class SecurityAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    severity: str
    priority_score: int = Field(ge=0, le=100)
    summary: str
    actor_type: str
    actor_reference: str
    status: AlertStatus = AlertStatus.OPEN
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AlertStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_status: AlertStatus
    changed_by: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)


class AlertTransition(BaseModel):
    transition_id: str = Field(default_factory=lambda: str(uuid4()))
    alert_id: str
    previous_status: AlertStatus
    new_status: AlertStatus
    changed_by: str
    reason: str
    timestamp: datetime = Field(default_factory=utc_now)
