import numpy as np
import pytest

from ai.risk_prediction.explainability import (
    RiskPredictionExplainer,
)
from ai.risk_prediction.xgboost_model import (
    XGBoostRiskPredictionModel,
)
from ai.security_context_schema import (
    SECURITY_CONTEXT_FEATURE_COUNT,
    SECURITY_CONTEXT_FEATURE_NAMES,
)


@pytest.fixture
def trained_model():
    """Create a small fitted four-class XGBoost model."""

    features = [
        [float((sample + feature) % 3) for feature in range(
            SECURITY_CONTEXT_FEATURE_COUNT
        )]
        for sample in range(40)
    ]

    labels = [
        "low",
        "medium",
        "high",
        "critical",
    ] * 10

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)

    return model, features


@pytest.fixture
def explainer(trained_model):
    model, _ = trained_model
    return RiskPredictionExplainer(model)


def test_explainer_rejects_unfitted_model():
    model = XGBoostRiskPredictionModel()

    with pytest.raises(
        RuntimeError,
        match="unfitted model",
    ):
        RiskPredictionExplainer(model)


def test_explainer_generates_one_explanation_per_sample(
    explainer,
    trained_model,
):
    _, features = trained_model

    explanations = explainer.explain(features[:3])

    assert len(explanations) == 3


def test_endpoint_explanation_contains_four_risk_classes(
    explainer,
    trained_model,
):
    _, features = trained_model

    explanation = explainer.explain(features[:1])[0]

    assert explanation.predicted_label in {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert set(explanation.probabilities) == {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert len(explanation.class_explanations) == 4

    assert {
        item.risk_class
        for item in explanation.class_explanations
    } == {
        "low",
        "medium",
        "high",
        "critical",
    }


def test_each_class_explanation_contains_all_features(
    explainer,
    trained_model,
):
    _, features = trained_model

    explanation = explainer.explain(features[:1])[0]

    for class_explanation in explanation.class_explanations:
        assert len(class_explanation.contributions) == (
            SECURITY_CONTEXT_FEATURE_COUNT
        )

        assert {
            item.feature_name
            for item in class_explanation.contributions
        } == set(SECURITY_CONTEXT_FEATURE_NAMES)


def test_feature_contributions_preserve_input_values(
    explainer,
    trained_model,
):
    _, features = trained_model

    explanation = explainer.explain(features[:1])[0]

    contributions = (
        explanation.class_explanations[0].contributions
    )

    for index, contribution in enumerate(contributions):
        assert contribution.feature_name == (
            SECURITY_CONTEXT_FEATURE_NAMES[index]
        )

        assert contribution.feature_value == features[0][index]


def test_global_feature_importance_returns_all_features(
    explainer,
    trained_model,
):
    _, features = trained_model

    importance = explainer.global_feature_importance(
        features[:10]
    )

    assert len(importance) == SECURITY_CONTEXT_FEATURE_COUNT

    values = [
        item["mean_absolute_shap"]
        for item in importance
    ]

    assert all(value >= 0 for value in values)
    assert values == sorted(values, reverse=True)


def test_class_feature_importance_returns_four_classes(
    explainer,
    trained_model,
):
    _, features = trained_model

    importance = explainer.class_feature_importance(
        features[:10]
    )

    assert set(importance) == {
        "low",
        "medium",
        "high",
        "critical",
    }

    for class_importance in importance.values():
        assert len(class_importance) == (
            SECURITY_CONTEXT_FEATURE_COUNT
        )

        values = [
            item["mean_absolute_shap"]
            for item in class_importance
        ]

        assert values == sorted(values, reverse=True)


def test_shap_additivity_validation_passes(
    explainer,
    trained_model,
):
    _, features = trained_model

    result = explainer.validate_additivity(features[:5])

    assert result["passed"] is True
    assert result["checks"] == 20
    assert result["maximum_absolute_error"] <= (
        result["tolerance"]
    )


def test_explainer_rejects_invalid_feature_count(explainer):
    invalid_features = [[0.0, 1.0, 2.0]]

    with pytest.raises(
        ValueError,
        match="Feature vector",
    ):
        explainer.explain(invalid_features)


def test_explainer_rejects_empty_features(explainer):
    with pytest.raises(
        ValueError,
        match="At least one feature vector",
    ):
        explainer.explain([])


def test_additivity_rejects_non_positive_tolerance(
    explainer,
    trained_model,
):
    _, features = trained_model

    with pytest.raises(
        ValueError,
        match="tolerance must be greater than zero",
    ):
        explainer.validate_additivity(
            features[:1],
            tolerance=0,
        )


def test_explanation_values_are_finite(
    explainer,
    trained_model,
):
    _, features = trained_model

    explanation = explainer.explain(features[:2])

    for sample in explanation:
        for class_explanation in sample.class_explanations:
            assert np.isfinite(class_explanation.base_value)
            assert np.isfinite(class_explanation.raw_model_output)

            for contribution in class_explanation.contributions:
                assert np.isfinite(contribution.shap_value)
                assert np.isfinite(contribution.feature_value)
