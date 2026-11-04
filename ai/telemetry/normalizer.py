"""Normalization helpers for incoming telemetry."""


def normalize_event(event):
    """Return a validated event using the canonical model representation."""
    from ai.telemetry.models import TelemetryEvent

    if isinstance(event, TelemetryEvent):
        return event
    return TelemetryEvent.model_validate(event)
