import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.app.api.discovery as discovery_api
from backend.app.main import app


client = TestClient(app)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "sample_openapi.json"
)


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def ensure_model_available():
    """Train the model only if the saved artifact is missing."""

    if not discovery_api.MODEL_PATH.is_file():
        from scripts.train_risk_prediction_model import (
            train_and_save_model,
        )

        train_and_save_model()


def test_shap_is_not_included_by_default():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert "shap_explainability" not in data

    for assessment in data["endpoint_assessments"]:
        assert "shap_explanation" not in assessment


def test_shap_explanations_are_returned_when_requested():
    ensure_model_available()

    response = client.post(
        "/api/discovery/assess?include_explanations=true",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["shap_explainability"]["available"] is True
    assert (
        data["shap_explainability"]["method"]
        == "SHAP TreeExplainer"
    )

    global_importance = (
        data["shap_explainability"]["global_feature_importance"]
    )

    assert len(global_importance) <= 10
    assert global_importance

    assert len(data["endpoint_assessments"]) == (
        data["inventory"]["total_endpoints"]
    )

    for assessment in data["endpoint_assessments"]:
        explanation = assessment["shap_explanation"]

        assert explanation["available"] is True

        assert explanation["predicted_class"] == (
            assessment["ml_risk_prediction"]["predicted_label"]
        )

        assert set(explanation["probabilities"]) == {
            "low",
            "medium",
            "high",
            "critical",
        }

        assert len(explanation["class_explanations"]) == 4
        assert len(explanation["top_features"]) <= 5

        for class_explanation in explanation["class_explanations"]:
            assert class_explanation["risk_class"] in {
                "low",
                "medium",
                "high",
                "critical",
            }

            assert len(class_explanation["top_features"]) <= 5

            for feature in class_explanation["top_features"]:
                assert feature["feature_name"]
                assert isinstance(feature["feature_value"], float)
                assert isinstance(feature["shap_value"], float)

                assert feature["direction"] in {
                    "increases_class_score",
                    "decreases_class_score",
                    "no_effect",
                }


def test_shap_can_be_requested_without_a_model_artifact(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        discovery_api,
        "MODEL_PATH",
        tmp_path / "missing_model.json",
    )

    response = client.post(
        "/api/discovery/assess?include_explanations=true",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["ml_model"]["available"] is False
    assert data["shap_explainability"]["available"] is False

    for assessment in data["endpoint_assessments"]:
        assert assessment["shap_explanation"]["available"] is False
        assert assessment["baseline_risk"] is not None
        assert assessment["security_evidence"] is not None


def test_shap_does_not_change_existing_ml_predictions():
    ensure_model_available()

    spec = load_fixture()

    normal_response = client.post(
        "/api/discovery/assess",
        json=spec,
    )

    explained_response = client.post(
        "/api/discovery/assess?include_explanations=true",
        json=spec,
    )

    assert normal_response.status_code == 200
    assert explained_response.status_code == 200

    normal_data = normal_response.json()
    explained_data = explained_response.json()

    assert normal_data["ml_model"] == explained_data["ml_model"]

    normal_assessments = normal_data["endpoint_assessments"]
    explained_assessments = explained_data["endpoint_assessments"]

    assert len(normal_assessments) == len(explained_assessments)

    for normal, explained in zip(
        normal_assessments,
        explained_assessments,
    ):
        assert normal["path"] == explained["path"]
        assert normal["method"] == explained["method"]

        assert normal["ml_risk_prediction"] == (
            explained["ml_risk_prediction"]
        )

        assert normal["baseline_risk"] == explained["baseline_risk"]
        assert normal["security_evidence"] == (
            explained["security_evidence"]
        )


def test_shap_global_importance_is_sorted():
    ensure_model_available()

    response = client.post(
        "/api/discovery/assess?include_explanations=true",
        json=load_fixture(),
    )

    assert response.status_code == 200

    importance = (
        response.json()["shap_explainability"][
            "global_feature_importance"
        ]
    )

    values = [
        item["mean_absolute_shap"]
        for item in importance
    ]

    assert values == sorted(values, reverse=True)
    assert all(value >= 0 for value in values)
