from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ai.telemetry.models import TelemetryBatch, TelemetryEvent
from ai.telemetry.processor import aggregate_events
from ai.telemetry.store import TelemetryEventStore
import backend.app.api.telemetry as telemetry_api
from backend.app.main import app


client = TestClient(app)


def make_event(**overrides):
    data = {
        "timestamp": datetime(2026, 11, 4, 10, 0, 10, tzinfo=timezone.utc),
        "method": "get",
        "endpoint_path": "/api/users",
        "status_code": 200,
        "latency_ms": 50,
        "response_size_bytes": 1000,
        "identity_hash": "identity-a",
        "client_hash": "client-a",
    }
    data.update(overrides)
    return TelemetryEvent(**data)


def test_event_normalizes_method_and_timestamp():
    event = make_event()
    assert event.method == "GET"
    assert event.timestamp.tzinfo is not None


@pytest.mark.parametrize(
    "path",
    [
        "api/users",
        "/api/users?token=secret",
        "/api/users#fragment",
        "/api/users\\admin",
    ],
)
def test_event_rejects_invalid_endpoint_path(path):
    with pytest.raises(ValidationError):
        make_event(endpoint_path=path)


def test_event_rejects_unexpected_sensitive_fields():
    data = make_event().model_dump()
    data["authorization"] = "Bearer secret"
    with pytest.raises(ValidationError):
        TelemetryEvent.model_validate(data)


def test_batch_rejects_duplicate_event_ids():
    event = make_event()
    with pytest.raises(ValidationError):
        TelemetryBatch(events=[event, event])


def test_store_persists_events_and_enforces_retention(tmp_path):
    store = TelemetryEventStore(tmp_path / "events.jsonl", max_events=2)

    events = [
        make_event(event_id="one"),
        make_event(event_id="two"),
        make_event(event_id="three"),
    ]

    assert store.append_events(events) == 3

    retained = store.read_events()
    assert [event.event_id for event in retained] == ["two", "three"]


def test_store_returns_empty_when_file_does_not_exist(tmp_path):
    store = TelemetryEventStore(tmp_path / "missing.jsonl")
    assert store.read_events() == []


def test_aggregation_calculates_behavioral_metrics():
    events = [
        make_event(event_id="one", status_code=200, latency_ms=20),
        make_event(
            event_id="two",
            status_code=401,
            latency_ms=40,
            identity_hash="identity-b",
            client_hash="client-b",
        ),
        make_event(event_id="three", status_code=500, latency_ms=60),
    ]

    observations = aggregate_events(events)

    assert len(observations) == 1
    observation = observations[0]

    assert observation.request_count == 3
    assert observation.unique_identity_count == 2
    assert observation.unique_client_count == 2
    assert observation.client_error_count == 1
    assert observation.server_error_count == 1
    assert observation.auth_failure_count == 1
    assert observation.mean_latency_ms == 40
    assert observation.data_origin == "runtime"


def test_aggregation_separates_endpoints_and_methods():
    events = [
        make_event(event_id="one"),
        make_event(event_id="two", endpoint_path="/api/orders"),
        make_event(event_id="three", method="POST"),
    ]

    observations = aggregate_events(events)
    assert len(observations) == 3


def test_aggregation_separates_time_windows():
    events = [
        make_event(event_id="one"),
        make_event(
            event_id="two",
            timestamp=datetime(
                2026, 11, 4, 10, 1, 10, tzinfo=timezone.utc
            ),
        ),
    ]

    assert len(aggregate_events(events, window_seconds=60)) == 2


def test_telemetry_api_accepts_batch_without_behavioral_model(
    monkeypatch,
    tmp_path,
):
    store = TelemetryEventStore(tmp_path / "events.jsonl")
    monkeypatch.setattr(telemetry_api, "get_telemetry_store", lambda: store)
    monkeypatch.setattr(
        telemetry_api, "load_behavioral_model", lambda: None
    )

    response = client.post(
        "/api/telemetry/events",
        json={
            "events": [
                make_event(event_id="one").model_dump(mode="json"),
                make_event(
                    event_id="two",
                    status_code=401,
                ).model_dump(mode="json"),
            ]
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "accepted"
    assert data["events_received"] == 2
    assert data["observations_generated"] == 1
    assert data["behavioral_assessment"] == "model_unavailable"
    assert len(store.read_events()) == 2


def test_telemetry_api_rejects_invalid_batch():
    response = client.post(
        "/api/telemetry/events",
        json={"events": []},
    )
    assert response.status_code == 422


def test_telemetry_api_uses_global_api_auth(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "true")
    monkeypatch.setenv("AEGISAI_API_KEY", "telemetry-test-secret")
    monkeypatch.setattr(
        telemetry_api,
        "get_telemetry_store",
        lambda: TelemetryEventStore(tmp_path / "events.jsonl"),
    )

    response = client.post(
        "/api/telemetry/events",
        json={"events": [make_event().model_dump(mode="json")]},
    )

    assert response.status_code == 401

    authenticated = client.post(
        "/api/telemetry/events",
        headers={"X-AegisAI-API-Key": "telemetry-test-secret"},
        json={"events": [make_event().model_dump(mode="json")]},
    )

    assert authenticated.status_code == 200


def test_telemetry_api_runs_detection_and_knowledge_ingestion(
    monkeypatch,
    tmp_path,
):
    from unittest.mock import Mock

    store = TelemetryEventStore(tmp_path / "events.jsonl")
    monkeypatch.setattr(
        telemetry_api, "get_telemetry_store", lambda: store
    )

    result = Mock()
    result.classification = "anomalous"
    result.model_dump.return_value = {
        "endpoint_path": "/api/users",
        "method": "GET",
        "classification": "anomalous",
        "anomaly_score": 0.42,
        "signals": [],
        "data_origin": "runtime",
        "limitations": ["Anomaly does not prove malicious activity."],
    }

    detector = Mock()
    detector.predict.return_value = [result]
    monkeypatch.setattr(
        telemetry_api, "load_behavioral_model", lambda: detector
    )

    knowledge_service = Mock()
    monkeypatch.setattr(
        telemetry_api,
        "get_knowledge_ingestion_service",
        lambda: knowledge_service,
    )

    response = client.post(
        "/api/telemetry/events",
        json={
            "events": [
                make_event(event_id="integration-test").model_dump(
                    mode="json"
                )
            ]
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "accepted"
    assert data["behavioral_assessment"] == "completed"
    assert data["observations_generated"] == 1
    assert data["anomalous_observations"] == 1

    detector.predict.assert_called_once()
    knowledge_service.ingest_behavioral.assert_called_once_with(
        [result.model_dump.return_value],
        "telemetry_ingestion",
    )

    assert len(store.read_events()) == 1
