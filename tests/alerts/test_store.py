from ai.alerts import AlertEngine, AlertStatus, AlertStore
from types import SimpleNamespace


def make_incident(**overrides):
    values = {
        "incident_id": "incident-alert-001",
        "severity": "high",
        "priority_score": 80,
        "summary": "Repeated authentication failures",
        "actor_type": "identity",
        "actor_reference": "pseudonymous-actor",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_alert_created_from_incident(tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    alert, created = AlertEngine(store).create_from_incident(make_incident())

    assert created is True
    assert alert.incident_id == "incident-alert-001"
    assert alert.status == AlertStatus.OPEN


def test_alert_creation_is_idempotent(tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    engine = AlertEngine(store)

    first, created_first = engine.create_from_incident(make_incident())
    second, created_second = engine.create_from_incident(make_incident())

    assert created_first is True
    assert created_second is False
    assert first.alert_id == second.alert_id
    assert len(store.list_alerts()) == 1


def test_alert_status_transitions_and_audit(tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    alert, _ = AlertEngine(store).create_from_incident(make_incident())

    transition = store.update_status(
        alert.alert_id,
        AlertStatus.ACKNOWLEDGED,
        "analyst-1",
        "Investigation started",
    )

    assert transition.previous_status == AlertStatus.OPEN
    assert transition.new_status == AlertStatus.ACKNOWLEDGED
    assert store.get_alert(alert.alert_id).status == AlertStatus.ACKNOWLEDGED
    assert len(store.get_audit(alert.alert_id)) == 2


def test_resolved_alert_cannot_be_reopened(tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    alert, _ = AlertEngine(store).create_from_incident(make_incident())

    store.update_status(
        alert.alert_id,
        AlertStatus.RESOLVED,
        "analyst-1",
        "Investigation completed",
    )

    try:
        store.update_status(
            alert.alert_id,
            AlertStatus.OPEN,
            "analyst-1",
            "Reopen",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Resolved alert should be terminal")


def test_alert_filtering(tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    first, _ = AlertEngine(store).create_from_incident(make_incident())
    store.update_status(
        first.alert_id,
        AlertStatus.ACKNOWLEDGED,
        "analyst-1",
        "Review",
    )

    assert len(store.list_alerts(status=AlertStatus.ACKNOWLEDGED)) == 1
    assert len(store.list_alerts(status=AlertStatus.OPEN)) == 0


def test_missing_alert_returns_none(tmp_path):
    store = AlertStore(tmp_path / "alerts.jsonl")
    assert store.get_alert("missing") is None
