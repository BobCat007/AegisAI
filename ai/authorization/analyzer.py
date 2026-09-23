from ai.authorization.findings import AuthorizationFinding
from ai.authorization.models import AuthorizationProbe, AuthorizationProbeResult


def analyze_authorization_probe(
    probe: AuthorizationProbe,
    result: AuthorizationProbeResult,
) -> AuthorizationFinding:
    """
    Compare the expected authorization outcome with the observed response.

    This function evaluates authorization behavior only. It does not infer
    a specific vulnerability type such as BOLA or BFLA.
    """

    if probe.expected_outcome == "allow":
        consistent = 200 <= result.status_code < 400
    else:
        consistent = result.status_code in {401, 403}

    return AuthorizationFinding(
        identity=probe.context.identity,
        expected_outcome=probe.expected_outcome,
        observed_status_code=result.status_code,
        status="consistent" if consistent else "inconsistent",
    )
