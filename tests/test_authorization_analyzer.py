from ai.authorization.analyzer import analyze_authorization_probe
from ai.authorization.models import (
    AuthorizationProbe,
    AuthorizationProbeResult,
    AuthorizationTestContext,
)


def test_allow_expectation_with_success_response_is_consistent():
    probe = AuthorizationProbe(
        method="GET",
        url="https://example.test/api/users/1",
        context=AuthorizationTestContext(
            identity="user-a",
            role="user",
            authenticated=True,
        ),
        expected_outcome="allow",
    )

    result = AuthorizationProbeResult(
        status_code=200,
        response_time_ms=25.0,
        response_size=128,
    )

    finding = analyze_authorization_probe(probe, result)

    assert finding.identity == "user-a"
    assert finding.expected_outcome == "allow"
    assert finding.observed_status_code == 200
    assert finding.status == "consistent"


def test_deny_expectation_with_forbidden_response_is_consistent():
    probe = AuthorizationProbe(
        method="GET",
        url="https://example.test/api/users/1",
        context=AuthorizationTestContext(
            identity="user-b",
            role="user",
            authenticated=True,
        ),
        expected_outcome="deny",
    )

    result = AuthorizationProbeResult(
        status_code=403,
        response_time_ms=25.0,
        response_size=64,
    )

    finding = analyze_authorization_probe(probe, result)

    assert finding.identity == "user-b"
    assert finding.expected_outcome == "deny"
    assert finding.observed_status_code == 403
    assert finding.status == "consistent"


def test_deny_expectation_with_success_response_is_inconsistent():
    probe = AuthorizationProbe(
        method="GET",
        url="https://example.test/api/users/1",
        context=AuthorizationTestContext(
            identity="user-b",
            role="user",
            authenticated=True,
        ),
        expected_outcome="deny",
    )

    result = AuthorizationProbeResult(
        status_code=200,
        response_time_ms=25.0,
        response_size=128,
    )

    finding = analyze_authorization_probe(probe, result)

    assert finding.status == "inconsistent"


def test_allow_expectation_with_unauthorized_response_is_inconsistent():
    probe = AuthorizationProbe(
        method="GET",
        url="https://example.test/api/users/1",
        context=AuthorizationTestContext(
            identity="user-a",
            role="user",
            authenticated=True,
        ),
        expected_outcome="allow",
    )

    result = AuthorizationProbeResult(
        status_code=401,
        response_time_ms=25.0,
        response_size=32,
    )

    finding = analyze_authorization_probe(probe, result)

    assert finding.status == "inconsistent"


def test_other_status_code_is_inconsistent_for_deny_expectation():
    probe = AuthorizationProbe(
        method="GET",
        url="https://example.test/api/users/1",
        context=AuthorizationTestContext(
            identity="user-b",
            role="user",
            authenticated=True,
        ),
        expected_outcome="deny",
    )

    result = AuthorizationProbeResult(
        status_code=500,
        response_time_ms=25.0,
        response_size=32,
    )

    finding = analyze_authorization_probe(probe, result)

    assert finding.status == "inconsistent"
