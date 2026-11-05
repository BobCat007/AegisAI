from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import backend.app.api.telemetry as telemetry_api
from ai.telemetry.models import TelemetryEvent
from ai.telemetry.store import TelemetryEventStore
from backend.app.main import app


client = TestClient(app)


def make_event(event_id, timestamp, path, status):
    return TelemetryEvent(
        event_id=event_id,
        timestamp=timestamp,
        method="GET",
        endpoint_path=path,
        status_code=status,
        latency_ms=25,
        identity_hash="private-identity",
        client_hash="private-client",
    )


def test_analytics_aggregates_retained_events(monkeypatch, tmp_path):
    now = datetime.now(timezone.utc)

    events = [
        make_event("one", now - timedelta(minutes=2), "/api/users", 200),
        make_event("two", now - timedelta(minutes=3), "/api/users", 401),
        make_event("three", now - timedelta(minutes=4), "/api/orders", 403),
        make_event("four", now - timedelta(minutes=5), "/api/users", 500),
        make_event("five", now - timedelta(minutes=6), "/api/orders", 302),
    ]

    store = TelemetryEventStore(tmp_path / "events.jsonl")
    store.append_events(events)

    monkeypatch.setattr(
        telemetry_api, "get_telemetry_store", lambda: store
    )

    response = client.get(
        "/api/telemetry/analytics?lookback_minutes=60&bucket_minutes=5"
    )

    assert response.status_code == 200
    data = response.json()

    assert data["events_analyzed"] == 5
    assert data["authentication_failures"] == 2
    assert data["status_distribution"] == {
        "2xx": 1,
        "3xx": 1,
        "4xx": 2,
        "5xx": 1,
        "other": 0,
    }

    assert data["top_endpoints"][0] == {
        "endpoint": "/api/users",
        "count": 3,
    }

    assert data["request_volume"]
    assert "identity_hash" not in str(data)
    assert "client_hash" not in str(data)


def test_analytics_excludes_events_outside_lookback(
    monkeypatch, tmp_path
):
    now = datetime.now(timezone.utc)

    store = TelemetryEventStore(tmp_path / "events.jsonl")
    store.append_events([
        make_event(
            "recent", now - timedelta(minutes=2), "/api/users", 200
        ),
        make_event(
            "old", now - timedelta(hours=3), "/api/users", 500
        ),
    ])

    monkeypatch.setattr(
        telemetry_api, "get_telemetry_store", lambda: store
    )

    response = client.get(
        "/api/telemetry/analytics?lookback_minutes=60"
    )

    assert response.status_code == 200
    assert response.json()["events_analyzed"] == 1


def test_analytics_rejects_invalid_parameters():
    assert client.get(
        "/api/telemetry/analytics?lookback_minutes=0"
    ).status_code == 422

    assert client.get(
        "/api/telemetry/analytics?bucket_minutes=120"
    ).status_code == 422

