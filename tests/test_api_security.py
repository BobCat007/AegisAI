from fastapi.testclient import TestClient

from backend.app.main import app
import backend.app.security as security
from backend.app.security import reset_rate_limit_state


client = TestClient(app)


def test_global_api_auth_is_disabled_for_local_development(monkeypatch):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "false")
    response = client.get("/api/copilot/status")
    assert response.status_code == 200


def test_global_api_auth_fails_closed_when_key_is_not_configured(monkeypatch):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "true")
    monkeypatch.delenv("AEGISAI_API_KEY", raising=False)

    response = client.get("/api/copilot/status")
    assert response.status_code == 503


def test_global_api_auth_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "true")
    monkeypatch.setenv("AEGISAI_API_KEY", "test-global-secret")

    response = client.get("/api/copilot/status")
    assert response.status_code == 401


def test_global_api_auth_accepts_valid_key(monkeypatch):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "true")
    monkeypatch.setenv("AEGISAI_API_KEY", "test-global-secret")

    response = client.get(
        "/api/copilot/status",
        headers={"X-AegisAI-API-Key": "test-global-secret"},
    )
    assert response.status_code == 200


def test_health_endpoint_remains_public(monkeypatch):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "true")
    monkeypatch.delenv("AEGISAI_API_KEY", raising=False)

    response = client.get("/health")
    assert response.status_code == 200


def test_rate_limiter_returns_429_after_configured_limit(monkeypatch):
    reset_rate_limit_state()
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "false")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_REQUESTS", "1")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_WINDOW_SECONDS", "60")

    try:
        first = client.get("/api/security-test-rate-limit")
        second = client.get("/api/security-test-rate-limit")

        assert first.status_code == 404
        assert second.status_code == 429
        assert "Retry-After" in second.headers
    finally:
        reset_rate_limit_state()


def test_rate_limit_is_shared_across_api_routes(monkeypatch):
    reset_rate_limit_state()
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "false")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_REQUESTS", "1")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_WINDOW_SECONDS", "60")

    try:
        first = client.get("/api/security-test-route-one")
        second = client.get("/api/security-test-route-two")

        assert first.status_code == 404
        assert second.status_code == 429
    finally:
        reset_rate_limit_state()


def test_rate_limiter_bounds_buckets_and_reclaims_expired_entries(monkeypatch):
    reset_rate_limit_state()

    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "false")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_REQUESTS", "100")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_WINDOW_SECONDS", "60")
    monkeypatch.setenv("AEGISAI_RATE_LIMIT_MAX_BUCKETS", "1")

    clock = {"now": 100.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: clock["now"])

    try:
        assert security._rate_limit_response("client-a") is None

        # A second client cannot allocate a bucket while capacity is full.
        clock["now"] = 101.0
        blocked = security._rate_limit_response("client-b")
        assert blocked.status_code == 503
        assert "Retry-After" in blocked.headers

        # Expired entries are reclaimed.
        clock["now"] = 161.0
        recovered = security._rate_limit_response("client-b")
        assert recovered is None
    finally:
        reset_rate_limit_state()


def test_global_api_auth_is_enabled_by_default(monkeypatch):
    monkeypatch.delenv("AEGISAI_API_AUTH_ENABLED", raising=False)
    monkeypatch.setenv("AEGISAI_API_KEY", "test-global-secret")

    rejected = client.get("/api/copilot/status")
    assert rejected.status_code == 401

    accepted = client.get(
        "/api/copilot/status",
        headers={"X-AegisAI-API-Key": "test-global-secret"},
    )
    assert accepted.status_code == 200


def test_security_headers_are_present_on_successful_response(monkeypatch):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "false")

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Permissions-Policy"] == (
        "camera=(), microphone=(), geolocation=()"
    )


def test_security_headers_are_present_on_rejected_response(monkeypatch):
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "true")
    monkeypatch.delenv("AEGISAI_API_KEY", raising=False)

    response = client.get("/api/copilot/status")

    assert response.status_code == 503
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
