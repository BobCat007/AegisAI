from types import SimpleNamespace

import pytest

from ai.incident_response import (
    IncidentResponseEngine,
    IncidentResponseStore,
    ResponseActionType,
    ResponsePolicy,
)


def make_incident(
    severity="high",
    indicators=None,
    actor_type="identity",
    actor_reference="pseudonymous-actor-123",
):
    return SimpleNamespace(
        incident_id="incident-test-001",
        severity=severity,
        indicators=indicators or ["authentication_failure"],
        actor_type=actor_type,
        actor_reference=actor_reference,
    )


def test_default_policy_generates_safe_dry_run_recommendations(tmp_path):
    store = IncidentResponseStore(tmp_path / "audit.jsonl")
    plan = IncidentResponseEngine(store).plan(make_incident())

    actions = {decision.action for decision in plan.decisions}

    assert plan.dry_run is True
    assert ResponseActionType.CREATE_ALERT in actions
    assert ResponseActionType.REQUEST_HUMAN_REVIEW in actions
    assert ResponseActionType.WATCH_ACTOR in actions
    assert ResponseActionType.RECOMMEND_RATE_LIMIT in actions
    assert all(decision.executed is False for decision in plan.decisions)
    assert all(
        decision.execution_status == "simulated"
        for decision in plan.decisions
    )
    assert len(store.read_records()) == 1


def test_low_severity_incident_is_below_default_threshold():
    plan = IncidentResponseEngine().plan(make_incident(severity="low"))

    assert plan.decisions == []
    assert any("below the policy threshold" in item for item in plan.limitations)


def test_medium_incident_does_not_receive_rate_limit_recommendation():
    plan = IncidentResponseEngine().plan(make_incident(
        severity="medium",
        indicators=["authentication_failure"],
    ))

    assert ResponseActionType.RECOMMEND_RATE_LIMIT not in {
        decision.action for decision in plan.decisions
    }


def test_rate_limit_is_only_recommended_for_high_severity_relevant_signal():
    plan = IncidentResponseEngine().plan(make_incident(
        severity="high",
        indicators=["authentication_failure"],
    ))

    assert ResponseActionType.RECOMMEND_RATE_LIMIT in {
        decision.action for decision in plan.decisions
    }


def test_actor_watch_recommendation_requires_actor_reference():
    plan = IncidentResponseEngine().plan(make_incident(actor_reference=""))

    assert ResponseActionType.WATCH_ACTOR not in {
        decision.action for decision in plan.decisions
    }


def test_policy_can_disable_response():
    plan = IncidentResponseEngine().plan(
        make_incident(),
        ResponsePolicy(enabled=False),
    )

    assert plan.decisions == []


def test_policy_can_restrict_allowed_actions():
    plan = IncidentResponseEngine().plan(
        make_incident(),
        ResponsePolicy(
            allowed_actions=[ResponseActionType.CREATE_ALERT],
        ),
    )

    assert [decision.action for decision in plan.decisions] == [
        ResponseActionType.CREATE_ALERT
    ]


def test_non_dry_run_still_does_not_execute_actions():
    plan = IncidentResponseEngine().plan(
        make_incident(),
        ResponsePolicy(dry_run=False),
    )

    assert all(decision.executed is False for decision in plan.decisions)
    rate_limit = next(
        decision for decision in plan.decisions
        if decision.action == ResponseActionType.RECOMMEND_RATE_LIMIT
    )
    assert rate_limit.execution_status == "approval_required"
    assert rate_limit.approval_required is True


def test_unknown_severity_is_rejected():
    with pytest.raises(ValueError, match="Unsupported incident severity"):
        IncidentResponseEngine().plan(make_incident(severity="extreme"))
