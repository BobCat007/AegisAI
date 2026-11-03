from fastapi.testclient import TestClient

import backend.app.api.behavioral as behavioral_api
from backend.app.main import app

from ai.behavioral_intelligence import (
    IsolationForestBehavioralDetector,
)
from ai.behavioral_intelligence.synthetic import (
    generate_normal_observations,
)


client = TestClient(app)


def build_payload():
    observation = {
        "endpoint_path": "/api/users",
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
    }

    return {
        "observations": [observation],
    }


def train_temporary_model(monkeypatch, tmp_path):
    model_path = tmp_path / "behavioral_model.joblib"

    detector = IsolationForestBehavioralDetector()
    detector.fit(
        generate_normal_observations(count=300)
    )
    detector.save(model_path)

    monkeypatch.setattr(
        behavioral_api,
        "BEHAVIORAL_MODEL_PATH",
        model_path,
    )


def test_behavioral_api_returns_503_without_model(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        behavioral_api,
        "BEHAVIORAL_MODEL_PATH",
        tmp_path / "missing.joblib",
    )

    response = client.post(
        "/api/behavior/assess",
        json=build_payload(),
    )

    assert response.status_code == 503


def test_behavioral_api_assesses_observations(
    monkeypatch,
    tmp_path,
):
    train_temporary_model(monkeypatch, tmp_path)

    response = client.post(
        "/api/behavior/assess",
        json=build_payload(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["model_type"] == "isolation_forest"
    assert data["model_available"] is True
    assert data["observations_assessed"] == 1
    assert len(data["results"]) == 1

    result = data["results"][0]

    assert result["endpoint_path"] == "/api/users"
    assert result["method"] == "GET"
    assert result["classification"] in {
        "normal",
        "anomalous",
    }


def test_behavioral_api_rejects_invalid_observation():
    payload = build_payload()
    payload["observations"][0]["request_count"] = -1

    response = client.post(
        "/api/behavior/assess",
        json=payload,
    )

    assert response.status_code == 422


def test_behavioral_api_rejects_empty_observations():
    response = client.post(
        "/api/behavior/assess",
        json={"observations": []},
    )

    assert response.status_code == 422


def test_behavioral_assessment_ingests_returned_results(monkeypatch, tmp_path):
    train_temporary_model(monkeypatch, tmp_path)
    calls = []

    class IngestionSpy:
        def ingest_behavioral(self, results, source_reference):
            calls.append((results, source_reference))

    monkeypatch.setattr(
        behavioral_api, "get_knowledge_ingestion_service", lambda: IngestionSpy()
    )
    response = client.post("/api/behavior/assess", json=build_payload())

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(calls) == 1
    assert calls[0][0] == data["results"]
    assert calls[0][1] == "behavioral_assessment"


def test_behavioral_success_is_not_failed_by_ingestion_error(monkeypatch, tmp_path):
    train_temporary_model(monkeypatch, tmp_path)

    class FailingIngestion:
        def ingest_behavioral(self, results, source_reference):
            raise RuntimeError("simulated knowledge index failure")

    monkeypatch.setattr(
        behavioral_api, "get_knowledge_ingestion_service", lambda: FailingIngestion()
    )
    response = client.post("/api/behavior/assess", json=build_payload())

    assert response.status_code == 200
    assert response.json()["status"] == "success"
