from ai.authorization.bfla import analyze_bfla_access
from ai.authorization.bola import analyze_bola_access
from ai.authorization.client import AuthorizationProbeClient
from ai.authorization.findings import AuthorizationSecurityFinding
from ai.authorization.models import (
    AuthorizationObservation,
    AuthorizationProbe,
    FunctionAuthorizationPolicy,
)
from ai.authorization.target_policy import AuthorizationTargetPolicy


def _validate_probe(
    probe: AuthorizationProbe,
    target_policy: AuthorizationTargetPolicy,
) -> list[str]:
    return target_policy.validate(probe.url)


def _to_observation(
    probe: AuthorizationProbe,
    result,
    resource_id: str,
    owner_identity: str,
    operation: str,
) -> AuthorizationObservation:
    return AuthorizationObservation(
        identity=probe.context.identity,
        role=probe.context.role,
        authenticated=probe.context.authenticated,
        resource_id=resource_id,
        owner_identity=owner_identity,
        operation=operation,
        expected_outcome=probe.expected_outcome,
        status_code=result.status_code,
        response_size=result.response_size,
        response_fingerprint=result.response_fingerprint,
        response_truncated=result.response_truncated,
    )


class AuthorizationTestOrchestrator:
    """
    Executes explicitly supplied authorization scenarios against
    explicitly allowlisted targets.
    """

    def __init__(
        self,
        client: AuthorizationProbeClient | None = None,
        target_policy: AuthorizationTargetPolicy | None = None,
    ) -> None:
        self.client = client or AuthorizationProbeClient()
        self.target_policy = target_policy or AuthorizationTargetPolicy()

    def run_bola_comparison(
        self,
        owner_probe: AuthorizationProbe,
        cross_user_probe: AuthorizationProbe,
        resource_id: str,
        owner_identity: str,
        operation: str,
    ) -> AuthorizationSecurityFinding:

        if owner_probe.url != cross_user_probe.url:
            raise ValueError("Both probes must target the same resource URL.")

        if owner_probe.method.upper() != cross_user_probe.method.upper():
            raise ValueError("Both probes must use the same HTTP method.")

        if owner_probe.query_params != cross_user_probe.query_params:
            raise ValueError("Both probes must use the same query parameters.")

        if owner_probe.body != cross_user_probe.body:
            raise ValueError("Both probes must use the same request body.")

        if owner_probe.context.identity != owner_identity:
            raise ValueError("Owner probe identity must match owner_identity.")

        if cross_user_probe.context.identity == owner_identity:
            raise ValueError("Cross-user probe must use a different identity.")

        if owner_probe.expected_outcome != "allow":
            raise ValueError("Owner probe must expect allow.")

        if cross_user_probe.expected_outcome != "deny":
            raise ValueError("Cross-user probe must expect deny.")

        resolved_addresses = _validate_probe(
            owner_probe,
            self.target_policy,
        )

        owner_result = self.client.execute(
            owner_probe,
            resolved_addresses=resolved_addresses,
        )

        cross_user_result = self.client.execute(
            cross_user_probe,
            resolved_addresses=resolved_addresses,
        )

        owner_observation = _to_observation(
            owner_probe,
            owner_result,
            resource_id,
            owner_identity,
            operation,
        )

        cross_user_observation = _to_observation(
            cross_user_probe,
            cross_user_result,
            resource_id,
            owner_identity,
            operation,
        )

        return analyze_bola_access(
            owner_observation,
            cross_user_observation,
        )

    def run_bfla_probe(
        self,
        probe: AuthorizationProbe,
        policy: FunctionAuthorizationPolicy,
        resource_id: str = "not-applicable",
    ) -> AuthorizationSecurityFinding:

        resolved_addresses = _validate_probe(
            probe,
            self.target_policy,
        )

        result = self.client.execute(
            probe,
            resolved_addresses=resolved_addresses,
        )

        observation = _to_observation(
            probe,
            result,
            resource_id,
            "not-applicable",
            policy.operation,
        )

        return analyze_bfla_access(observation, policy)
