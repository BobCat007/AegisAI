from types import SimpleNamespace

from fastapi.testclient import TestClient

import backend.app.api.telemetry as telemetry_api
from ai.incident_response import IncidentResponseStore
from backend.app.main import app


client = TestClient(app)


def make_incident():
    return SimpleNamespace(
        incident_id="incident-api-001",
        severity="high",
        indicators=["authentication_failure"],
        actor_type="identity",
        actor_reference="pseudonymous-actor-123",
    )


def configure_api(monkeypatch, tmp_path):
    store = IncidentResponseStore(tmp_path / "response_audit.jsonl")
    incident = make_incident()

    monkeypatch.setattr(
        telemetry_api,
        "get_response_store",
        lambda: store,
    )
    monkeypatch.setattr(
        telemetry_api,
        "correlate_recent_incidents",
        lambda **kwargs: SimpleNamespace(incidents=[incident]),
    )

    return store, incident


def test_create_response_plan_api(monkeypatch, tmp_path):
    store, incident = configure_api(monkeypatch, tmp_path)

    response = client.post(
        f"/api/telemetry/incidents/{incident.incident_id}/response-plan"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == incident.incident_id
    assert data["dry_run"] is True
    assert data["decisions"]
    assert all(item["executed"] is False for item in data["decisions"])
    assert len(store.read_records()) == 1


def test_create_response_plan_respects_supplied_policy(
    monkeypatch,
    tmp_path,
):
    _, incident = configure_api(monkeypatch, tmp_path)

    response = client.post(
        f"/api/telemetry/incidents/{incident.incident_id}/response-plan",
        json={
            "policy_id": "alert_only",
            "dry_run": True,
            "allowed_actions": ["create_alert"],
        },
    )

    assert response.status_code == 200
    assert response.json()["policy_id"] == "alert_only"
    assert len(response.json()["decisions"]) == 1
    assert response.json()["decisions"][0]["action"] == "create_alert"


def test_response_plan_returns_404_for_unknown_incident(
    monkeypatch,
    tmp_path,
):
    configure_api(monkeypatch, tmp_path)

    response = client.post(
        "/api/telemetry/incidents/unknown-incident/response-plan"
    )

    assert response.status_code == 404


def test_lifecycle_api_records_valid_transitions(monkeypatch, tmp_path):
    store, incident = configure_api(monkeypatch, tmp_path)
    url = f"/api/telemetry/incidents/{incident.incident_id}/status"

    first = client.patch(
        url,
        json={
            "new_status": "investigating",
            "changed_by": "analyst-1",
            "reason": "Reviewing suspicious authentication activity",
        },
    )
    second = client.patch(
        url,
        json={
            "new_status": "contained",
            "changed_by": "analyst-1",
            "reason": "Containment approved",
        },
    )

    assert first.status_code == 200
    assert first.json()["previous_status"] == "suspected"
    assert second.status_code == 200
    assert second.json()["new_status"] == "contained"
    assert len(store.read_records()) == 2


def test_lifecycle_api_rejects_invalid_transition(monkeypatch, tmp_path):
    _, incident = configure_api(monkeypatch, tmp_path)
    url = f"/api/telemetry/incidents/{incident.incident_id}/status"

    response = client.patch(
        url,
        json={
            "new_status": "resolved",
            "changed_by": "analyst-1",
            "reason": "Trying to skip investigation",
        },
    )

    assert response.status_code == 409


def test_lifecycle_api_rejects_blank_audit_fields(monkeypatch, tmp_path):
    _, incident = configure_api(monkeypatch, tmp_path)

    response = client.patch(
        f"/api/telemetry/incidents/{incident.incident_id}/status",
        json={
            "new_status": "investigating",
            "changed_by": "   ",
            "reason": "Review started",
        },
    )

    assert response.status_code == 422


def test_lifecycle_api_rejects_unknown_incident(monkeypatch, tmp_path):
    store = IncidentResponseStore(tmp_path / "response_audit.jsonl")
    monkeypatch.setattr(
        telemetry_api,
        "get_response_store",
        lambda: store,
    )
    monkeypatch.setattr(
        telemetry_api,
        "correlate_recent_incidents",
        lambda **kwargs: SimpleNamespace(incidents=[]),
    )

    response = client.patch(
        "/api/telemetry/incidents/unknown-incident/status",
        json={
            "new_status": "investigating",
            "changed_by": "analyst-1",
            "reason": "Review started",
        },
    )

    assert response.status_code == 404


def test_response_audit_api_returns_incident_records(
    monkeypatch,
    tmp_path,
):
    store, incident = configure_api(monkeypatch, tmp_path)
    store.transition(
        incident.incident_id,
        __import__(
            "ai.incident_response",
            fromlist=["IncidentStatus"],
        ).IncidentStatus.INVESTIGATING,
        "analyst-1",
        "Review started",
    )

    response = client.get(
        f"/api/telemetry/incidents/{incident.incident_id}/response-audit"
    )

    assert response.status_code == 200
    assert response.json()["record_count"] == 1
    assert response.json()["records"][0]["record_type"] == "lifecycle_transition"


def test_response_audit_api_returns_404_when_empty(monkeypatch, tmp_path):
    configure_api(monkeypatch, tmp_path)

    response = client.get(
        "/api/telemetry/incidents/incident-with-no-audit/response-audit"
    )

    assert response.status_code == 404
