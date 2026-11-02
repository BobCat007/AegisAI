import pytest

from ai.authorization.bfla import analyze_bfla_access
from ai.authorization.models import (
    AuthorizationObservation,
    FunctionAuthorizationPolicy,
)


def make_observation(
    role="user",
    authenticated=True,
    status_code=200,
):
    return AuthorizationObservation(
        identity="user-a",
        role=role,
        authenticated=authenticated,
        resource_id="not-applicable",
        owner_identity="not-applicable",
        operation="DELETE /api/admin/users/{id}",
        expected_outcome="deny",
        status_code=status_code,
        response_size=64,
    )


def make_policy():
    return FunctionAuthorizationPolicy(
        operation="DELETE /api/admin/users/{id}",
        permitted_roles=["admin"],
        requires_authentication=True,
    )


def test_bfla_suspected_for_unauthorized_role_with_success():
    finding = analyze_bfla_access(
        make_observation(role="user", status_code=200),
        make_policy(),
    )

    assert finding.finding_type == "bfla"
    assert finding.status == "suspected"
    assert finding.severity == "medium"
    assert finding.confidence == 0.75
    assert finding.evidence["operation_execution_verified"] is False


def test_bfla_not_detected_when_unauthorized_role_is_denied():
    finding = analyze_bfla_access(
        make_observation(role="user", status_code=403),
        make_policy(),
    )

    assert finding.status == "not_detected"


def test_bfla_not_detected_for_permitted_admin():
    finding = analyze_bfla_access(
        make_observation(role="admin", status_code=200),
        make_policy(),
    )

    assert finding.status == "not_detected"


def test_bfla_detects_missing_authentication():
    finding = analyze_bfla_access(
        make_observation(
            role="admin",
            authenticated=False,
            status_code=200,
        ),
        make_policy(),
    )

    assert finding.status == "suspected"


def test_bfla_inconclusive_on_application_error():
    finding = analyze_bfla_access(
        make_observation(role="user", status_code=500),
        make_policy(),
    )

    assert finding.status == "inconclusive"


def test_bfla_rejects_operation_mismatch():
    observation = make_observation()
    observation.operation = "GET /api/users"

    with pytest.raises(ValueError):
        analyze_bfla_access(observation, make_policy())
