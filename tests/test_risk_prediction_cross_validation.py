from ai.risk_prediction.cross_validation import (
    run_stratified_cross_validation,
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
            raise RuntimeError(
                "Model must be fitted before prediction."
            )

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


def build_test_dataset():
    features = [
        [float(index), float(index + 1)]
        for index in range(40)
    ]

    labels = (
        ["low"] * 20
        + ["medium"] * 10
        + ["high"] * 6
        + ["critical"] * 4
    )

    return features, labels


def test_cross_validation_returns_expected_number_of_folds():
    features, labels = build_test_dataset()

    results = run_stratified_cross_validation(
        MockRiskPredictionModel,
        features,
        labels,
        n_splits=3,
    )

    assert results["n_splits"] == 3
    assert len(results["folds"]) == 3


def test_cross_validation_contains_fold_sizes():
    features, labels = build_test_dataset()

    results = run_stratified_cross_validation(
        MockRiskPredictionModel,
        features,
        labels,
        n_splits=3,
    )

    for fold in results["folds"]:
        assert fold["train_size"] + fold["validation_size"] == 40
        assert fold["train_size"] > fold["validation_size"]


def test_cross_validation_contains_metrics():
    features, labels = build_test_dataset()

    results = run_stratified_cross_validation(
        MockRiskPredictionModel,
        features,
        labels,
        n_splits=3,
    )

    for fold in results["folds"]:
        metrics = fold["metrics"]

        assert "accuracy" in metrics
        assert "precision_macro" in metrics
        assert "recall_macro" in metrics
        assert "f1_macro" in metrics
        assert "confusion_matrix" in metrics


def test_cross_validation_returns_mean_metrics():
    features, labels = build_test_dataset()

    results = run_stratified_cross_validation(
        MockRiskPredictionModel,
        features,
        labels,
        n_splits=3,
    )

    assert 0.0 <= results["mean_accuracy"] <= 1.0
    assert 0.0 <= results["mean_precision_macro"] <= 1.0
    assert 0.0 <= results["mean_recall_macro"] <= 1.0
    assert 0.0 <= results["mean_f1_macro"] <= 1.0


def test_cross_validation_rejects_invalid_model_factory():
    features, labels = build_test_dataset()

    def invalid_factory():
        return object()

    try:
        run_stratified_cross_validation(
            invalid_factory,
            features,
            labels,
            n_splits=3,
        )
    except TypeError as error:
        assert str(error) == (
            "model_factory must return a RiskPredictionModel."
        )
    else:
        raise AssertionError(
            "Expected TypeError for invalid model factory."
        )
