from ai.authorization.models import (
    AuthorizationProbe,
    AuthorizationProbeResult,
)


def test_authorization_probe_defaults():
    probe = AuthorizationProbe(
        method="GET",
        url="https://example.test/api/users/1",
    )

    assert probe.method == "GET"
    assert probe.url == "https://example.test/api/users/1"
    assert probe.headers == {}
    assert probe.query_params == {}
    assert probe.body is None


def test_authorization_probe_accepts_request_data():
    probe = AuthorizationProbe(
        method="POST",
        url="https://example.test/api/users",
        headers={"Authorization": "Bearer test-token"},
        query_params={"page": "1"},
        body={"name": "test"},
    )

    assert probe.method == "POST"
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
