from pathlib import Path

import pytest

from ai.graph_intelligence.builder import build_security_graph
from ai.risk_prediction.xgboost_model import XGBoostRiskPredictionModel
from ai.security_context_features import build_security_context_feature_vector
from scripts.generate_training_data import (
    generate_endpoint_templates,
    get_risk_label,
)


def build_training_data():
    endpoints = generate_endpoint_templates()
    graph = build_security_graph([])

    features = [
        build_security_context_feature_vector(endpoint, graph)
        for endpoint in endpoints
    ]
    labels = [get_risk_label(endpoint) for endpoint in endpoints]

    return endpoints, features, labels


def test_xgboost_model_accepts_aegisai_endpoint_features():
    endpoints, features, labels = build_training_data()

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)
    predictions = model.predict(features)

    assert len(predictions) == len(endpoints)
    assert all(len(vector) == 31 for vector in features)
    assert set(predictions).issubset(model.LABEL_TO_INDEX)


def test_xgboost_model_rejects_empty_training_data():
    model = XGBoostRiskPredictionModel()

    with pytest.raises(ValueError, match="at least one feature vector"):
        model.fit([], [])


def test_xgboost_model_rejects_mismatched_training_data():
    model = XGBoostRiskPredictionModel()

    with pytest.raises(ValueError, match="same number"):
        model.fit([[0.0] * 31], ["low", "medium"])


def test_xgboost_model_rejects_invalid_feature_count():
    model = XGBoostRiskPredictionModel()

    with pytest.raises(ValueError, match="expected 31"):
        model.fit([[0.0] * 25], ["low"])


def test_xgboost_model_rejects_invalid_labels():
    model = XGBoostRiskPredictionModel()

    with pytest.raises(ValueError, match="label"):
        model.fit([[0.0] * 31], ["unknown"])


def test_xgboost_model_requires_training_before_prediction():
    model = XGBoostRiskPredictionModel()

    with pytest.raises(RuntimeError, match="not been fitted or loaded"):
        model.predict([[0.0] * 31])


def test_xgboost_model_rejects_invalid_prediction_feature_count():
    _, features, labels = build_training_data()

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)

    with pytest.raises(ValueError, match="expected 31"):
        model.predict([[0.0] * 25])


def test_xgboost_model_predicts_probabilities():
    endpoints, features, labels = build_training_data()

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)

    probabilities = model.predict_proba(features)

    assert len(probabilities) == len(endpoints)

    for row in probabilities:
        assert set(row.keys()) == set(model.LABEL_TO_INDEX.keys())
        assert all(0.0 <= value <= 1.0 for value in row.values())
        assert sum(row.values()) == pytest.approx(1.0, abs=1e-5)


def test_xgboost_model_save_and_load(tmp_path: Path):
    _, features, labels = build_training_data()

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)

    artifact_path = tmp_path / "models" / "risk_model.json"
    model.save(artifact_path)

    loaded_model = XGBoostRiskPredictionModel.load(artifact_path)

    assert artifact_path.exists()
    assert loaded_model.predict(features) == model.predict(features)
    assert loaded_model.predict_proba(features) == pytest.approx(
        model.predict_proba(features)
    )


def test_xgboost_model_cannot_save_before_training(tmp_path: Path):
    model = XGBoostRiskPredictionModel()

    with pytest.raises(RuntimeError, match="before it has been fitted"):
        model.save(tmp_path / "risk_model.json")


def test_xgboost_model_load_rejects_missing_artifact(tmp_path: Path):
    artifact_path = tmp_path / "missing_model.json"

    with pytest.raises(FileNotFoundError):
        XGBoostRiskPredictionModel.load(artifact_path)
