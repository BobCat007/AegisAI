from types import SimpleNamespace

from fastapi.testclient import TestClient

import backend.app.api.telemetry as telemetry_api
from ai.alerts import AlertEngine, AlertStore
from backend.app.main import app


client = TestClient(app)


def make_incident():
    return SimpleNamespace(
        incident_id="incident-api-alert",
        severity="high",
        priority_score=80,
        summary="Repeated authentication failures",
        actor_type="identity",
        actor_reference="test-actor",
    )


def configure(monkeypatch, tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    monkeypatch.setattr(telemetry_api, "get_alert_store", lambda: store)
    return store


def test_list_alerts_api(monkeypatch, tmp_path):
    store = configure(monkeypatch, tmp_path)
    AlertEngine(store).create_from_incident(make_incident())

    response = client.get("/api/telemetry/alerts")

    assert response.status_code == 200
    assert response.json()["count"] == 1


def test_get_alert_api(monkeypatch, tmp_path):
    store = configure(monkeypatch, tmp_path)
    alert, _ = AlertEngine(store).create_from_incident(make_incident())

    response = client.get(f"/api/telemetry/alerts/{alert.alert_id}")

    assert response.status_code == 200
    assert response.json()["incident_id"] == alert.incident_id


def test_update_alert_status_api(monkeypatch, tmp_path):
    store = configure(monkeypatch, tmp_path)
    alert, _ = AlertEngine(store).create_from_incident(make_incident())

    response = client.patch(
        f"/api/telemetry/alerts/{alert.alert_id}/status",
        json={
            "new_status": "acknowledged",
            "changed_by": "analyst-1",
            "reason": "Review started",
        },
    )

    assert response.status_code == 200
    assert response.json()["new_status"] == "acknowledged"


def test_update_alert_rejects_invalid_transition(monkeypatch, tmp_path):
    store = configure(monkeypatch, tmp_path)
    alert, _ = AlertEngine(store).create_from_incident(make_incident())

    response = client.patch(
        f"/api/telemetry/alerts/{alert.alert_id}/status",
        json={
            "new_status": "open",
            "changed_by": "analyst-1",
            "reason": "Invalid transition",
        },
    )

    assert response.status_code == 409


def test_alert_audit_api(monkeypatch, tmp_path):
    store = configure(monkeypatch, tmp_path)
    alert, _ = AlertEngine(store).create_from_incident(make_incident())

    store.update_status(
        alert.alert_id,
        __import__("ai.alerts", fromlist=["AlertStatus"]).AlertStatus.ACKNOWLEDGED,
        "analyst-1",
        "Review started",
    )

    response = client.get(
        f"/api/telemetry/alerts/{alert.alert_id}/audit"
    )

    assert response.status_code == 200
    assert response.json()["record_count"] == 2


def test_unknown_alert_returns_404(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)

    response = client.get("/api/telemetry/alerts/unknown-alert")

    assert response.status_code == 404
