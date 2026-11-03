import pytest
import json
from pathlib import Path

from fastapi.testclient import TestClient

import backend.app.api.discovery as discovery_api
from backend.app.main import app
from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES


client = TestClient(app)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "sample_openapi.json"
)


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_integrated_assessment_returns_success():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["assessment_type"] == "openapi_static_analysis"
    assert data["vulnerabilities_confirmed"] is False


def test_integrated_assessment_includes_inventory_and_graph():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["inventory"]["title"] == "AegisAI Demo API"
    assert data["inventory"]["total_endpoints"] == 5

    assert "objects" in data["security_graph"]
    assert "operations" in data["security_graph"]
    assert isinstance(data["graph_features"], dict)


def test_integrated_assessment_covers_every_endpoint():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()
    assessments = data["endpoint_assessments"]

    assert len(assessments) == data["inventory"]["total_endpoints"]
    assert data["summary"]["assessed_endpoints"] == len(assessments)

    for assessment in assessments:
        assert assessment["path"]
        assert assessment["method"]

        baseline = assessment["baseline_risk"]

        assert 0 <= baseline["score"] <= 100
        assert baseline["severity"] in {
            "low",
            "medium",
            "high",
            "critical",
        }


def test_security_context_vectors_match_the_feature_schema():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["summary"]["security_context_feature_count"]
        == len(SECURITY_CONTEXT_FEATURE_NAMES)
    )

    for assessment in data["endpoint_assessments"]:
        context = assessment["security_context"]

        assert context["feature_names"] == list(
            SECURITY_CONTEXT_FEATURE_NAMES
        )

        assert len(context["feature_vector"]) == len(
            SECURITY_CONTEXT_FEATURE_NAMES
        )

        assert all(
            isinstance(value, (int, float))
            for value in context["feature_vector"]
        )


def test_integrated_assessment_rejects_invalid_specification():
    response = client.post(
        "/api/discovery/assess",
        json={"openapi": "3.0.3", "paths": "invalid"},
    )

    assert response.status_code == 400
    assert response.json()["detail"].startswith(
        "Unable to assess OpenAPI specification:"
    )


def test_integrated_assessment_includes_security_evidence():
    from ai.risk_prediction.evidence import CRAPI_SECURITY_EVIDENCE

    spec = load_fixture()
    evidence = CRAPI_SECURITY_EVIDENCE[0]

    spec["paths"][evidence.path] = {
        "delete": {
            "operationId": "delete_other_users_video",
            "responses": {
                "204": {"description": "Deleted"},
            },
        },
    }

    response = client.post(
        "/api/discovery/assess",
        json=spec,
    )

    assert response.status_code == 200

    data = response.json()
    assessment = next(
        item
        for item in data["endpoint_assessments"]
        if (
            item["path"] == evidence.path
            and item["method"] == evidence.method
        )
    )

    correlated = assessment["security_evidence"]

    assert correlated["has_security_evidence"] is True
    assert correlated["vulnerability_types"] == ["BFLA"]
    assert correlated["predicted_label"] in {"low", "medium", "high"}
    assert correlated["evidence_details"][0]["source"] == "OWASP crAPI"

    assert (
        data["summary"]["endpoints_matching_documented_evidence"] == 1
    )


def test_unmatched_endpoint_has_no_documented_security_evidence():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        correlated = assessment["security_evidence"]

        assert correlated["has_security_evidence"] is False
        assert correlated["vulnerability_types"] == []
        assert correlated["evidence_details"] == []
        assert correlated["predicted_label"] in {"low", "medium", "high"}


def test_evidence_correlation_does_not_claim_vulnerability_confirmation():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["vulnerabilities_confirmed"] is False
    assert data["evidence_catalog"] == "CRAPI_SECURITY_EVIDENCE"


def test_ml_predictions_are_returned_when_model_is_available(
    monkeypatch,
):
    from ai.risk_prediction.xgboost_model import XGBoostRiskPredictionModel

    model = XGBoostRiskPredictionModel()
    model_path = discovery_api.MODEL_PATH

    if not model_path.is_file():
        # Avoid depending on a developer's local artifact.
        from scripts.train_risk_prediction_model import train_and_save_model

        train_and_save_model()

    monkeypatch.setattr(
        discovery_api,
        "MODEL_PATH",
        model_path,
    )

    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["ml_model"]["available"] is True
    assert data["ml_model"]["predictions_are_experimental"] is True
    assert data["summary"]["ml_predictions_available"] is True

    for assessment in data["endpoint_assessments"]:
        prediction = assessment["ml_risk_prediction"]

        assert prediction["available"] is True
        assert prediction["model_type"] == "xgboost"
        assert prediction["training_data"] == "synthetic"
        assert prediction["predicted_label"] in {
            "low",
            "medium",
            "high",
            "critical",
        }

        probabilities = prediction["class_probabilities"]

        assert set(probabilities) == {
            "low",
            "medium",
            "high",
            "critical",
        }
        assert sum(probabilities.values()) == pytest.approx(1.0, abs=1e-5)

        # The baseline assessment remains independently available.
        assert "baseline_risk" in assessment
        assert "security_evidence" in assessment


def test_static_assessment_continues_when_model_artifact_is_missing(
    monkeypatch,
    tmp_path,
):
    missing_model_path = tmp_path / "missing_model.json"

    monkeypatch.setattr(
        discovery_api,
        "MODEL_PATH",
        missing_model_path,
    )

    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["ml_model"]["available"] is False
    assert data["summary"]["ml_predictions_available"] is False

    for assessment in data["endpoint_assessments"]:
        prediction = assessment["ml_risk_prediction"]

        assert prediction["available"] is False
        assert prediction["predicted_label"] is None
        assert prediction["class_probabilities"] is None
        assert "baseline_risk" in assessment
        assert "security_evidence" in assessment


def test_discovery_ingests_successful_assessment(monkeypatch):
    calls = []

    class IngestionSpy:
        def ingest_discovery(self, assessment):
            calls.append(assessment)

    monkeypatch.setattr(
        discovery_api, "get_knowledge_ingestion_service", lambda: IngestionSpy()
    )
    response = client.post("/api/discovery/assess", json=load_fixture())

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert len(calls) == 1
    assert calls[0]["status"] == "success"


def test_discovery_success_is_not_failed_by_ingestion_error(monkeypatch):
    class FailingIngestion:
        def ingest_discovery(self, assessment):
            raise RuntimeError("simulated knowledge index failure")

    monkeypatch.setattr(
        discovery_api, "get_knowledge_ingestion_service", lambda: FailingIngestion()
    )
    response = client.post("/api/discovery/assess", json=load_fixture())

    assert response.status_code == 200
    assert response.json()["status"] == "success"
