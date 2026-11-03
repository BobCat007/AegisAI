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
        path = "/api/security-test-rate-limit"
        first = client.get(path)
        second = client.get(path)

        # The first request reaches routing (this path intentionally does not exist).
        assert first.status_code == 404
        assert second.status_code == 429
        assert "Retry-After" in second.headers
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
        first = client.get("/api/security-capacity-first")
        assert first.status_code == 404

        # The only bucket is active, so a second distinct path is rejected.
        clock["now"] = 101.0
        blocked = client.get("/api/security-capacity-second")
        assert blocked.status_code == 503
        assert "Retry-After" in blocked.headers

        # Once the original bucket expires, its space can be reused.
        clock["now"] = 161.0
        recovered = client.get("/api/security-capacity-second")
        assert recovered.status_code == 404

    finally:
        reset_rate_limit_state()
