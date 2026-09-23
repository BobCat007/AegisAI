from ai.authorization.models import (
    AuthorizationProbe,
    AuthorizationProbeResult,
    AuthorizationTestContext,
)


def test_authorization_test_context_defaults():
    context = AuthorizationTestContext(
        identity="anonymous",
    )

    assert context.identity == "anonymous"
    assert context.role is None
    assert context.authenticated is False


def test_authorization_test_context_accepts_authenticated_identity():
    context = AuthorizationTestContext(
        identity="user-a",
        role="user",
        authenticated=True,
    )

    assert context.identity == "user-a"
    assert context.role == "user"
    assert context.authenticated is True


def test_authorization_probe_defaults():
    probe = AuthorizationProbe(
        method="GET",
        url="https://example.test/api/users/1",
        context=AuthorizationTestContext(
            identity="anonymous",
        ),
        expected_outcome="deny",
    )

    assert probe.method == "GET"
    assert probe.url == "https://example.test/api/users/1"
    assert probe.context.identity == "anonymous"
    assert probe.context.authenticated is False
    assert probe.expected_outcome == "deny"
    assert probe.headers == {}
    assert probe.query_params == {}
    assert probe.body is None


def test_authorization_probe_accepts_request_data():
    probe = AuthorizationProbe(
        method="POST",
        url="https://example.test/api/users",
        context=AuthorizationTestContext(
            identity="user-a",
            role="user",
            authenticated=True,
        ),
        expected_outcome="allow",
        headers={"Authorization": "Bearer test-token"},
        query_params={"page": "1"},
        body={"name": "test"},
    )

    assert probe.method == "POST"
    assert probe.context.identity == "user-a"
    assert probe.context.role == "user"
    assert probe.context.authenticated is True
    assert probe.expected_outcome == "allow"
    assert probe.headers["Authorization"] == "Bearer test-token"
    assert probe.query_params["page"] == "1"
    assert probe.body == {"name": "test"}


def test_authorization_probe_result():
    result = AuthorizationProbeResult(
        status_code=403,
        response_time_ms=42.5,
        response_size=128,
    )

    assert result.status_code == 403
    assert result.response_time_ms == 42.5
    assert result.response_size == 128
