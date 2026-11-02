from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)

API_KEY = "test-secret-key"
API_HEADERS = {"X-AegisAI-Auth-Key": API_KEY}


def valid_bfla_payload():
    return {
        "probe": {
            "method": "GET",
            "url": "http://127.0.0.1:8000/admin",
            "context": {
                "identity": "test-user",
                "role": "user",
                "authenticated": True,
            },
            "expected_outcome": "deny",
            "headers": {},
            "query_params": {},
            "body": None,
        },
        "policy": {
            "operation": "GET /admin",
            "permitted_roles": ["admin"],
            "requires_authentication": True,
        },
        "resource_id": "admin-resource",
    }


def valid_bola_payload():
    owner_probe = {
        "method": "GET",
        "url": "http://127.0.0.1:8000/api/documents/123",
        "context": {
            "identity": "owner-user",
            "role": "user",
            "authenticated": True,
        },
        "expected_outcome": "allow",
        "headers": {},
        "query_params": {},
        "body": None,
    }

    cross_user_probe = {
        "method": "GET",
        "url": "http://127.0.0.1:8000/api/documents/123",
        "context": {
            "identity": "other-user",
            "role": "user",
            "authenticated": True,
        },
        "expected_outcome": "deny",
        "headers": {},
        "query_params": {},
        "body": None,
    }

    return {
        "owner_probe": owner_probe,
        "cross_user_probe": cross_user_probe,
        "resource_id": "document-123",
        "owner_identity": "owner-user",
        "operation": "read",
    }


def enable_api(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_API_ENABLED", "true")
    monkeypatch.setenv("AEGISAI_AUTH_API_KEY", API_KEY)


def fake_finding(finding_type):
    return SimpleNamespace(
        model_dump=lambda: {
            "finding_type": finding_type,
            "status": "suspected",
            "severity": "medium",
            "confidence": 0.75,
            "title": f"Test {finding_type.upper()} finding",
            "description": "Synthetic finding for API integration testing.",
            "identity": "test-user",
            "resource_id": "test-resource",
            "operation": "test-operation",
            "evidence": {},
        }
    )


class FakeOrchestrator:
    def run_bola_comparison(self, **kwargs):
        return fake_finding("bola")

    def run_bfla_probe(self, **kwargs):
        return fake_finding("bfla")


def test_authorization_api_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AEGISAI_AUTH_API_ENABLED", raising=False)
    monkeypatch.delenv("AEGISAI_AUTH_API_KEY", raising=False)

    response = client.post(
        "/api/authorization/bfla/assess",
        json=valid_bfla_payload(),
    )

    assert response.status_code == 503


def test_authorization_api_requires_configured_key(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_API_ENABLED", "true")
    monkeypatch.delenv("AEGISAI_AUTH_API_KEY", raising=False)

    response = client.post(
        "/api/authorization/bfla/assess",
        json=valid_bfla_payload(),
    )

    assert response.status_code == 503


def test_authorization_api_rejects_missing_key(monkeypatch):
    enable_api(monkeypatch)

    response = client.post(
        "/api/authorization/bfla/assess",
        json=valid_bfla_payload(),
    )

    assert response.status_code == 401


def test_authorization_api_rejects_incorrect_key(monkeypatch):
    enable_api(monkeypatch)

    response = client.post(
        "/api/authorization/bfla/assess",
        headers={"X-AegisAI-Auth-Key": "wrong-key"},
        json=valid_bfla_payload(),
    )

    assert response.status_code == 401


def test_bfla_api_returns_successful_assessment(monkeypatch):
    enable_api(monkeypatch)

    monkeypatch.setattr(
        "backend.app.api.authorization.get_orchestrator",
        lambda: FakeOrchestrator(),
    )

    response = client.post(
        "/api/authorization/bfla/assess",
        headers=API_HEADERS,
        json=valid_bfla_payload(),
    )

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "success"
    assert data["finding"]["finding_type"] == "bfla"
    assert data["finding"]["status"] == "suspected"
    assert data["limitations"]


def test_bola_api_returns_successful_assessment(monkeypatch):
    enable_api(monkeypatch)

    monkeypatch.setattr(
        "backend.app.api.authorization.get_orchestrator",
        lambda: FakeOrchestrator(),
    )

    response = client.post(
        "/api/authorization/bola/assess",
        headers=API_HEADERS,
        json=valid_bola_payload(),
    )

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "success"
    assert data["finding"]["finding_type"] == "bola"
    assert data["finding"]["status"] == "suspected"
    assert data["limitations"]


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (ValueError("Invalid target URL."), 400),
        (TimeoutError("Target timed out."), 504),
        (ConnectionError("Target unavailable."), 502),
        (OSError("Network failure."), 502),
    ],
)
def test_bfla_api_maps_assessment_errors(
    monkeypatch,
    error,
    expected_status,
):
    enable_api(monkeypatch)

    class FailingOrchestrator:
        def run_bfla_probe(self, **kwargs):
            raise error

    monkeypatch.setattr(
        "backend.app.api.authorization.get_orchestrator",
        lambda: FailingOrchestrator(),
    )

    response = client.post(
        "/api/authorization/bfla/assess",
        headers=API_HEADERS,
        json=valid_bfla_payload(),
    )

    assert response.status_code == expected_status
