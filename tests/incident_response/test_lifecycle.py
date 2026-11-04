import pytest

from ai.incident_response import IncidentResponseStore, IncidentStatus


def test_incident_starts_as_suspected(tmp_path):
    store = IncidentResponseStore(tmp_path / "audit.jsonl")

    assert store.get_status("incident-1") == IncidentStatus.SUSPECTED


def test_valid_lifecycle_transitions_are_persisted(tmp_path):
    store = IncidentResponseStore(tmp_path / "audit.jsonl")

    first = store.transition(
        "incident-1",
        IncidentStatus.INVESTIGATING,
        "analyst-1",
        "Reviewing correlated authentication failures",
    )
    second = store.transition(
        "incident-1",
        IncidentStatus.CONTAINED,
        "analyst-1",
        "Containment approved and recorded",
    )
    third = store.transition(
        "incident-1",
        IncidentStatus.RESOLVED,
        "analyst-1",
        "Investigation completed",
    )

    assert first.previous_status == IncidentStatus.SUSPECTED
    assert second.previous_status == IncidentStatus.INVESTIGATING
    assert third.previous_status == IncidentStatus.CONTAINED
    assert store.get_status("incident-1") == IncidentStatus.RESOLVED
    assert len(store.read_records()) == 3


def test_false_positive_can_be_marked_from_suspected(tmp_path):
    store = IncidentResponseStore(tmp_path / "audit.jsonl")

    store.transition(
        "incident-2",
        IncidentStatus.FALSE_POSITIVE,
        "analyst-2",
        "Traffic matched an approved test",
    )

    assert store.get_status("incident-2") == IncidentStatus.FALSE_POSITIVE


def test_invalid_transition_is_rejected(tmp_path):
    store = IncidentResponseStore(tmp_path / "audit.jsonl")

    with pytest.raises(ValueError, match="Invalid incident transition"):
        store.transition(
            "incident-3",
            IncidentStatus.RESOLVED,
            "analyst-1",
            "Cannot resolve before investigation",
        )


def test_terminal_incident_cannot_be_reopened(tmp_path):
    store = IncidentResponseStore(tmp_path / "audit.jsonl")
    store.transition(
        "incident-4",
        IncidentStatus.FALSE_POSITIVE,
        "analyst-1",
        "False positive",
    )

    with pytest.raises(ValueError, match="Invalid incident transition"):
        store.transition(
            "incident-4",
            IncidentStatus.INVESTIGATING,
            "analyst-1",
            "Attempted reopen",
        )


@pytest.mark.parametrize("field,value", [
    ("incident_id", ""),
    ("changed_by", ""),
    ("reason", ""),
])
def test_transition_requires_audit_context(tmp_path, field, value):
    store = IncidentResponseStore(tmp_path / "audit.jsonl")
    args = {
        "incident_id": "incident-5",
        "new_status": IncidentStatus.INVESTIGATING,
        "changed_by": "analyst-1",
        "reason": "Review started",
    }
    args[field] = value

    with pytest.raises(ValueError):
        store.transition(**args)


def test_audit_store_ignores_malformed_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = IncidentResponseStore(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{bad json}\n", encoding="utf-8")

    store.transition(
        "incident-6",
        IncidentStatus.INVESTIGATING,
        "analyst-1",
        "Review started",
    )

    assert len(store.read_records()) == 1
