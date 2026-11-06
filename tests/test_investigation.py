from fastapi.testclient import TestClient

from backend.app.main import app
import backend.app.api.investigation as investigation_api

client = TestClient(app)


def openapi_payload():
    return {
        "openapi": "3.0.0",
        "info": {"title": "Investigation Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "responses": {"200": {"description": "Success"}}
                }
            }
        },
    }


def observation_payload():
    return [{
        "endpoint_path": "/users",
        "method": "GET",
        "window_seconds": 60,
        "request_count": 100,
        "unique_identity_count": 10,
        "unique_client_count": 5,
        "client_error_count": 4,
        "server_error_count": 1,
        "auth_failure_count": 2,
        "mean_latency_ms": 80,
        "latency_stddev_ms": 20,
        "mean_response_size_bytes": 1500,
        "response_size_stddev_bytes": 200,
        "data_origin": "runtime",
    }]


def payload(observations=None):
    return {
        "openapi_spec": openapi_payload(),
        "include_explanations": False,
        "behavioral_observations": (
            observation_payload() if observations is None else observations
        ),
    }


def test_static_investigation_succeeds_without_observations(monkeypatch):
    monkeypatch.setattr(
        investigation_api,
        "load_behavioral_model",
        lambda: None,
    )

    response = client.post(
        "/api/investigation/run",
        json=payload(observations=[]),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["phases"]["static_discovery"]["status"] == "completed"
    assert data["phases"]["behavioral"]["status"] == "skipped"


def test_behavioral_investigation_succeeds(monkeypatch):
    class FakeResult:
        classification = "anomalous"

        def model_dump(self, mode="json"):
            return {
                "endpoint_path": "/users",
                "method": "GET",
                "classification": "anomalous",
            }

    class FakeDetector:
        def predict(self, observations):
            assert len(observations) == 1
            return [FakeResult()]

    monkeypatch.setattr(
        investigation_api,
        "load_behavioral_model",
        lambda: FakeDetector(),
    )

    response = client.post(
        "/api/investigation/run",
        json=payload(),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["phases"]["static_discovery"]["status"] == "completed"
    assert data["phases"]["behavioral"]["status"] == "completed"
    assert data["phases"]["behavioral"]["observations_assessed"] == 1
    assert data["phases"]["behavioral"]["anomalous_observations"] == 1


def test_behavioral_phase_skips_when_model_unavailable(monkeypatch):
    monkeypatch.setattr(
        investigation_api,
        "load_behavioral_model",
        lambda: None,
    )

    response = client.post(
        "/api/investigation/run",
        json=payload(),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["phases"]["behavioral"]["status"] == "skipped"


def test_invalid_observation_is_rejected():
    invalid = observation_payload()
    invalid[0]["request_count"] = -1

    response = client.post(
        "/api/investigation/run",
        json=payload(observations=invalid),
    )

    assert response.status_code == 422


def test_static_failure_skips_behavioral_phase(monkeypatch):
    def fail_static(*args, **kwargs):
        raise RuntimeError("simulated static failure")

    monkeypatch.setattr(
        investigation_api,
        "assess_openapi",
        fail_static,
    )

    response = client.post(
        "/api/investigation/run",
        json=payload(observations=[]),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial_failure"
    assert data["phases"]["static_discovery"]["status"] == "failed"
    assert data["phases"]["behavioral"]["status"] == "skipped"


def test_behavioral_failure_preserves_static_results(monkeypatch):
    def fail_behavioral():
        raise RuntimeError("simulated model failure")

    monkeypatch.setattr(
        investigation_api,
        "load_behavioral_model",
        fail_behavioral,
    )

    response = client.post(
        "/api/investigation/run",
        json=payload(),
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial_failure"
    assert data["phases"]["static_discovery"]["status"] == "completed"
    assert data["phases"]["behavioral"]["status"] == "failed"
