from datetime import datetime, timezone

from fastapi.testclient import TestClient

import backend.app.api.telemetry as telemetry_api
from ai.telemetry.models import TelemetryEvent
from ai.telemetry.store import TelemetryEventStore
from backend.app.main import app


client = TestClient(app)


def make_event(event_id, **overrides):
    data = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc),
        "method": "POST",
        "endpoint_path": "/api/auth/login",
        "status_code": 401,
        "latency_ms": 40,
        "response_size_bytes": 100,
        "identity_hash": "test-identity",
        "client_hash": "test-client",
    }
    data.update(overrides)
    return TelemetryEvent(**data)


def test_post_events_returns_incident_summary(monkeypatch, tmp_path):
    store = TelemetryEventStore(tmp_path / "events.jsonl")

    monkeypatch.setattr(
        telemetry_api,
        "get_telemetry_store",
        lambda: store,
    )
    monkeypatch.setattr(
        telemetry_api,
        "load_behavioral_model",
        lambda: None,
    )

    events = [
        make_event(f"api-auth-{i}").model_dump(mode="json")
        for i in range(3)
    ]

    response = client.post(
        "/api/telemetry/events",
        json={"events": events},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "accepted"
    assert data["incident_correlation"] == "completed"
    assert data["incident_count"] >= 1
    assert any(
        incident["actor_type"] == "identity"
        for incident in data["incidents"]
    )


def test_get_incidents_reads_persisted_events(monkeypatch, tmp_path):
    store = TelemetryEventStore(tmp_path / "events.jsonl")
    store.append_events([
        make_event(f"get-auth-{i}")
        for i in range(3)
    ])

    monkeypatch.setattr(
        telemetry_api,
        "get_telemetry_store",
        lambda: store,
    )

    response = client.get("/api/telemetry/incidents")

    assert response.status_code == 200

    data = response.json()

    assert data["events_considered"] == 3
    assert data["correlation_window_seconds"] == 300
    assert any(
        incident["actor_type"] == "identity"
        for incident in data["incidents"]
    )


def test_get_incidents_accepts_custom_window(monkeypatch, tmp_path):
    store = TelemetryEventStore(tmp_path / "events.jsonl")

    monkeypatch.setattr(
        telemetry_api,
        "get_telemetry_store",
        lambda: store,
    )

    response = client.get(
        "/api/telemetry/incidents",
        params={
            "lookback_minutes": 30,
            "window_seconds": 600,
        },
    )

    assert response.status_code == 200
    assert response.json()["correlation_window_seconds"] == 600


def test_get_incidents_rejects_invalid_parameters():
    response = client.get(
        "/api/telemetry/incidents",
        params={"lookback_minutes": 0},
    )

    assert response.status_code == 422

    response = client.get(
        "/api/telemetry/incidents",
        params={"window_seconds": 30},
    )

    assert response.status_code == 422


def test_incident_failure_does_not_reject_persisted_telemetry(
    monkeypatch,
    tmp_path,
):
    store = TelemetryEventStore(tmp_path / "events.jsonl")

    monkeypatch.setattr(
        telemetry_api,
        "get_telemetry_store",
        lambda: store,
    )
    monkeypatch.setattr(
        telemetry_api,
        "load_behavioral_model",
        lambda: None,
    )

    def fail_correlation(**kwargs):
        raise RuntimeError("simulated correlation failure")

    monkeypatch.setattr(
        telemetry_api,
        "correlate_recent_incidents",
        fail_correlation,
    )

    response = client.post(
        "/api/telemetry/events",
        json={
            "events": [
                make_event("persist-before-correlation").model_dump(
                    mode="json"
                )
            ]
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert response.json()["incident_correlation"] == "failed"
    assert len(store.read_events()) == 1


def test_incidents_correlate_across_separate_ingestion_batches(
    monkeypatch,
    tmp_path,
):
    store = TelemetryEventStore(tmp_path / "events.jsonl")

    monkeypatch.setattr(
        telemetry_api,
        "get_telemetry_store",
        lambda: store,
    )
    monkeypatch.setattr(
        telemetry_api,
        "load_behavioral_model",
        lambda: None,
    )

    first_batch = [
        make_event(
            "batch-one-1",
            status_code=401,
            endpoint_path="/api/auth/login",
        ).model_dump(mode="json"),
        make_event(
            "batch-one-2",
            status_code=401,
            endpoint_path="/api/auth/login",
        ).model_dump(mode="json"),
    ]

    second_batch = [
        make_event(
            "batch-two-1",
            status_code=403,
            endpoint_path="/api/admin",
        ).model_dump(mode="json"),
    ]

    first_response = client.post(
        "/api/telemetry/events",
        json={"events": first_batch},
    )
    second_response = client.post(
        "/api/telemetry/events",
        json={"events": second_batch},
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    data = second_response.json()

    identity_incident = next(
        incident for incident in data["incidents"]
        if incident["actor_type"] == "identity"
    )

    assert identity_incident["event_count"] == 3
    assert identity_incident["distinct_endpoints"] == 2
    assert identity_incident["vulnerabilities_confirmed"] is False
