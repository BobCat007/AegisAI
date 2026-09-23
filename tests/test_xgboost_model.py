from ai.risk_prediction.xgboost_model import (
    XGBoostRiskPredictionModel,
)

from risk_engine.features import extract_feature_vector
from scripts.generate_training_data import (
    generate_endpoint_templates,
    get_risk_label,
)


def build_training_data():
    features = [
        [0.0, 0.0],
        [0.1, 0.1],
        [1.0, 1.0],
        [1.1, 1.1],
        [2.0, 2.0],
        [2.1, 2.1],
        [3.0, 3.0],
        [3.1, 3.1],
    ]

    labels = [
        "low",
        "low",
        "medium",
        "medium",
        "high",
        "high",
        "critical",
        "critical",
    ]

    return features, labels


def test_xgboost_model_implements_risk_prediction_interface():
    model = XGBoostRiskPredictionModel()

    assert isinstance(
        model,
        __import__(
            "ai.risk_prediction.model",
            fromlist=["RiskPredictionModel"],
        ).RiskPredictionModel,
    )


def test_xgboost_model_can_fit_and_predict():
    features, labels = build_training_data()

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)

    predictions = model.predict(features)

    assert len(predictions) == len(features)
    assert set(predictions).issubset(
        {
            "low",
            "medium",
            "high",
            "critical",
        }
    )


def test_xgboost_model_returns_class_probabilities():
    features, labels = build_training_data()

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)

    probabilities = model.predict_proba(features)

    assert len(probabilities) == len(features)

    for probability_map in probabilities:
        assert set(probability_map) == {
            "low",
            "medium",
            "high",
            "critical",
        }

        assert abs(
            sum(probability_map.values()) - 1.0
        ) < 1e-6

        assert all(
            0.0 <= probability <= 1.0
            for probability in probability_map.values()
        )

def test_xgboost_model_accepts_aegisai_endpoint_features():
    endpoints = generate_endpoint_templates()

    features = [
        extract_feature_vector(endpoint)
        for endpoint in endpoints
    ]

    labels = [
        get_risk_label(endpoint)
        for endpoint in endpoints
    ]

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)

    predictions = model.predict(features)

    assert len(predictions) == len(endpoints)
    assert all(
        len(feature_vector) == 22
        for feature_vector in features
    )
    assert set(predictions).issubset(
        {
            "low",
            "medium",
            "high",
            "critical",
        }
    )
