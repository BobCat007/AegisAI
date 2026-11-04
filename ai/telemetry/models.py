"""Validated, privacy-conscious API telemetry event models."""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TelemetryEvent(BaseModel):
    """One normalized API request/response metadata event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=64)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    method: str = Field(min_length=1, max_length=10)
    endpoint_path: str = Field(min_length=1, max_length=2048)
    status_code: int = Field(ge=100, le=599)
    latency_ms: float = Field(ge=0, le=3600000)
    response_size_bytes: int = Field(default=0, ge=0)

    # These fields must contain pseudonymous identifiers, not raw identities.
    identity_hash: str | None = Field(default=None, max_length=128)
    client_hash: str | None = Field(default=None, max_length=128)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        value = value.strip().upper()
        if not value.isalpha():
            raise ValueError("method must contain alphabetic HTTP method characters.")
        return value

    @field_validator("endpoint_path")
    @classmethod
    def validate_endpoint_path(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/"):
            raise ValueError("endpoint_path must start with '/'.")
        if any(char in value for char in ("?", "#", "\\", "\r", "\n")):
            raise ValueError("endpoint_path must not contain query strings or fragments.")
        if any(ord(char) < 32 for char in value):
            raise ValueError("endpoint_path contains invalid control characters.")
        return value

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone.")
        return value.astimezone(timezone.utc)

    @field_validator("identity_hash", "client_hash")
    @classmethod
    def normalize_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class TelemetryBatch(BaseModel):
    """Bounded batch of telemetry events."""

    model_config = ConfigDict(extra="forbid")

    events: list[TelemetryEvent] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def reject_duplicate_event_ids(self):
        identifiers = [event.event_id for event in self.events]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Duplicate event_id values are not allowed in a batch.")
        return self
