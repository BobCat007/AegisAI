from statistics import pstdev

import pytest

from ai.risk_prediction.cross_validation import (
    _calculate_fold_metric_summary,
    run_grouped_cross_validation,
)
from ai.risk_prediction.model import RiskPredictionModel


class MockRiskPredictionModel(RiskPredictionModel):
    def __init__(self):
        self.is_fitted = False

    def fit(
        self,
        features: list[list[float]],
        labels: list[str],
    ) -> None:
        self.is_fitted = True

    def predict(
        self,
        features: list[list[float]],
    ) -> list[str]:
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before prediction.")

        return ["low"] * len(features)

    def predict_proba(
        self,
        features: list[list[float]],
    ) -> list[dict[str, float]]:
        return [
            {
                "low": 1.0,
                "medium": 0.0,
                "high": 0.0,
                "critical": 0.0,
            }
            for _ in features
        ]


def build_grouped_dataset():
    features = []
    labels = []
    groups = []

    for class_index, class_name in enumerate(
        ["low", "medium", "high", "critical"]
    ):
        for endpoint_index in range(4):
            group = f"{class_name}_endpoint_{endpoint_index}"

            for scenario_index in range(3):
                features.append(
                    [
                        float(class_index),
                        float(endpoint_index),
                        float(scenario_index),
                    ]
                )
                labels.append(class_name)
                groups.append(group)

    return features, labels, groups


def test_grouped_cross_validation_returns_metric_standard_deviations():
    features, labels, groups = build_grouped_dataset()

    results = run_grouped_cross_validation(
        MockRiskPredictionModel,
        features,
        labels,
        groups,
        n_splits=3,
        random_state=42,
    )

    metric_names = [
        "accuracy",
        "precision_macro",
        "recall_macro",
        "f1_macro",
    ]

    for metric_name in metric_names:
        values = [
            fold["metrics"][metric_name]
            for fold in results["folds"]
        ]

        expected_std = pstdev(values)

        assert results[f"std_{metric_name}"] == expected_std
        assert results[f"std_{metric_name}"] >= 0.0


def test_grouped_cross_validation_preserves_mean_metrics():
    features, labels, groups = build_grouped_dataset()

    results = run_grouped_cross_validation(
        MockRiskPredictionModel,
        features,
        labels,
        groups,
        n_splits=3,
        random_state=42,
    )

    metric_names = [
        "accuracy",
        "precision_macro",
        "recall_macro",
        "f1_macro",
    ]

    for metric_name in metric_names:
        values = [
            fold["metrics"][metric_name]
            for fold in results["folds"]
        ]

        expected_mean = sum(values) / len(values)

        assert results[f"mean_{metric_name}"] == expected_mean


def test_identical_fold_metrics_have_zero_standard_deviation():
    fold_results = [
        {
            "metrics": {
                "accuracy": 0.8,
                "precision_macro": 0.7,
                "recall_macro": 0.6,
                "f1_macro": 0.65,
            }
        }
        for _ in range(3)
    ]

    summary = _calculate_fold_metric_summary(fold_results)

    assert summary["std_accuracy"] == 0.0
    assert summary["std_precision_macro"] == 0.0
    assert summary["std_recall_macro"] == 0.0
    assert summary["std_f1_macro"] == 0.0


def test_empty_fold_results_raise_value_error():
    with pytest.raises(
        ValueError,
        match="At least one fold result is required",
    ):
        _calculate_fold_metric_summary([])
