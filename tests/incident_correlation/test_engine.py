from datetime import datetime, timedelta, timezone

import pytest

from ai.telemetry.models import TelemetryEvent
from ai.incident_correlation import IncidentCorrelationEngine


BASE_TIME = datetime(2026, 11, 4, 10, 0, 10, tzinfo=timezone.utc)
NOW = BASE_TIME + timedelta(minutes=4)


def make_event(event_id, **overrides):
    data = {
        "event_id": event_id,
        "timestamp": BASE_TIME,
        "method": "GET",
        "endpoint_path": "/api/users",
        "status_code": 200,
        "latency_ms": 50,
        "response_size_bytes": 1000,
        "identity_hash": "identity-a",
        "client_hash": "client-a",
    }
    data.update(overrides)
    return TelemetryEvent(**data)


def test_three_authentication_failures_create_incident():
    events = [
        make_event(f"auth-{i}", status_code=401)
        for i in range(3)
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    identity_incidents = [
        item for item in result.incidents
        if item.actor_type == "identity"
    ]

    assert len(identity_incidents) == 1
    assert identity_incidents[0].severity == "medium"
    assert identity_incidents[0].event_count == 3
    assert identity_incidents[0].vulnerabilities_confirmed is False


def test_two_authentication_failures_across_endpoints_create_incident():
    events = [
        make_event("one", status_code=401, endpoint_path="/api/login"),
        make_event("two", status_code=403, endpoint_path="/api/admin"),
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    identity_incidents = [
        item for item in result.incidents
        if item.actor_type == "identity"
    ]

    assert len(identity_incidents) == 1
    assert identity_incidents[0].distinct_endpoints == 2


def test_five_server_errors_create_incident():
    events = [
        make_event(f"server-{i}", status_code=500)
        for i in range(5)
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    assert any(
        incident.actor_type == "identity"
        and "server_errors" in incident.indicators
        for incident in result.incidents
    )


def test_thirty_requests_create_high_volume_incident():
    events = [
        make_event(f"volume-{i}")
        for i in range(30)
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    incident = next(
        item for item in result.incidents
        if item.actor_type == "identity"
    )

    assert incident.event_count == 30
    assert "high_request_volume" in incident.indicators


def test_different_actors_are_not_merged():
    events = [
        make_event(
            f"actor-a-{i}",
            status_code=401,
            identity_hash="identity-a",
            client_hash=None,
        )
        for i in range(2)
    ] + [
        make_event(
            f"actor-b-{i}",
            status_code=401,
            identity_hash="identity-b",
            client_hash=None,
        )
        for i in range(2)
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    assert result.incidents == []


def test_events_without_hashes_are_not_actor_correlated():
    events = [
        make_event(
            f"anonymous-{i}",
            status_code=401,
            identity_hash=None,
            client_hash=None,
        )
        for i in range(5)
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    assert result.incidents == []
    assert result.events_considered == 5


def test_duplicate_event_ids_are_deduplicated():
    event = make_event("duplicate", status_code=401)

    result = IncidentCorrelationEngine().correlate(
        [event, event, event],
        now=NOW,
    )

    assert result.events_considered == 1
    assert result.incidents == []


def test_normal_low_volume_traffic_does_not_create_incident():
    events = [
        make_event(f"normal-{i}")
        for i in range(10)
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    assert result.incidents == []


def test_events_outside_lookback_are_excluded():
    events = [
        make_event(
            f"old-{i}",
            status_code=401,
            timestamp=NOW - timedelta(hours=2),
        )
        for i in range(5)
    ]

    result = IncidentCorrelationEngine().correlate(
        events,
        lookback_minutes=60,
        now=NOW,
    )

    assert result.events_considered == 0
    assert result.incidents == []


def test_future_events_are_excluded():
    events = [
        make_event(
            f"future-{i}",
            status_code=401,
            timestamp=NOW + timedelta(minutes=10),
        )
        for i in range(5)
    ]

    result = IncidentCorrelationEngine().correlate(events, now=NOW)

    assert result.events_considered == 0
    assert result.incidents == []


def test_incident_id_is_stable_for_same_actor_and_window():
    events = [
        make_event(f"stable-{i}", status_code=401)
        for i in range(3)
    ]

    engine = IncidentCorrelationEngine()

    first = engine.correlate(events, now=NOW)
    second = engine.correlate(events, now=NOW)

    first_id = next(
        item.incident_id for item in first.incidents
        if item.actor_type == "identity"
    )
    second_id = next(
        item.incident_id for item in second.incidents
        if item.actor_type == "identity"
    )

    assert first_id == second_id


def test_naive_now_is_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        IncidentCorrelationEngine().correlate(
            [],
            now=datetime(2026, 11, 4, 10, 0, 0),
        )


def test_invalid_lookback_is_rejected():
    with pytest.raises(ValueError, match="lookback_minutes"):
        IncidentCorrelationEngine().correlate([], lookback_minutes=0)
