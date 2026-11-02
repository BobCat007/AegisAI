from ai.authorization.findings import AuthorizationSecurityFinding
from ai.authorization.models import (
    AuthorizationObservation,
    FunctionAuthorizationPolicy,
)


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


def _is_access_denied(status_code: int) -> bool:
    return status_code in {401, 403, 404}


def analyze_bfla_access(
    observation: AuthorizationObservation,
    policy: FunctionAuthorizationPolicy,
) -> AuthorizationSecurityFinding:
    """
    Compare observed function access against an explicitly supplied policy.

    HTTP status codes alone cannot prove that a protected operation executed.
    """

    if observation.operation != policy.operation:
        raise ValueError(
            "The observation operation must match the authorization policy."
        )

    role_permitted = (
        observation.role is not None
        and observation.role in policy.permitted_roles
    )

    authentication_permitted = (
        not policy.requires_authentication or observation.authenticated
    )

    expected_allow = role_permitted and authentication_permitted
    observed_success = _is_success(observation.status_code)
    observed_denial = _is_access_denied(observation.status_code)

    evidence = {
        "identity": observation.identity,
        "role": observation.role,
        "authenticated": observation.authenticated,
        "operation": observation.operation,
        "permitted_roles": ",".join(policy.permitted_roles),
        "requires_authentication": policy.requires_authentication,
        "policy_expected_outcome": "allow" if expected_allow else "deny",
        "observed_status_code": observation.status_code,
        "operation_execution_verified": False,
    }

    if not expected_allow and observed_success:
        status = "suspected"
        severity = "medium"
        confidence = 0.75
        description = (
            "An identity not permitted by the supplied function policy "
            "received a successful HTTP response. This suggests possible "
            "broken function-level authorization, but operation execution "
            "has not been independently verified."
        )

    elif not expected_allow and observed_denial:
        status = "not_detected"
        severity = "informational"
        confidence = 0.9
        description = (
            "The operation was denied in accordance with the supplied "
            "function authorization policy."
        )

    elif not expected_allow:
        status = "inconclusive"
        severity = "informational"
        confidence = 0.4
        description = (
            "The response did not establish whether function authorization "
            "was enforced. The response may represent an application error."
        )

    elif observed_success:
        status = "not_detected"
        severity = "informational"
        confidence = 0.9
        description = (
            "The permitted identity received a successful response."
        )

    else:
        status = "inconclusive"
        severity = "informational"
        confidence = 0.5
        description = (
            "The identity was permitted by policy but the operation did not "
            "succeed. This does not independently establish a BFLA vulnerability."
        )

    return AuthorizationSecurityFinding(
        finding_type="bfla",
        status=status,
        severity=severity,
        confidence=confidence,
        title="Broken Function Level Authorization analysis",
        description=description,
        identity=observation.identity,
        resource_id=observation.resource_id,
        operation=observation.operation,
        evidence=evidence,
    )
