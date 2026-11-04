"""Telemetry validation helpers."""

from ai.telemetry.models import TelemetryBatch, TelemetryEvent


def validate_event(event) -> TelemetryEvent:
    return TelemetryEvent.model_validate(event)


def validate_batch(batch) -> TelemetryBatch:
    return TelemetryBatch.model_validate(batch)
