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


def build_grouped_test_dataset():
    features = []
    labels = []
    groups = []

    # Four endpoint groups per class, with three scenarios per endpoint.
    for class_label, class_name in enumerate(
        ["low", "medium", "high", "critical"]
    ):
        for endpoint_index in range(4):
            group = f"{class_name}_endpoint_{endpoint_index}"

            for scenario_index in range(3):
                features.append(
                    [float(class_label), float(endpoint_index), float(scenario_index)]
                )
                labels.append(class_name)
                groups.append(group)

    return features, labels, groups


def test_grouped_cross_validation_keeps_groups_separate():
    from ai.risk_prediction.cross_validation import (
        run_grouped_cross_validation,
    )

    features, labels, groups = build_grouped_test_dataset()

    results = run_grouped_cross_validation(
        MockRiskPredictionModel,
        features,
        labels,
        groups,
        n_splits=3,
    )

    assert results["n_splits"] == 3
    assert results["sample_count"] == len(features)
    assert results["group_count"] == len(set(groups))
    assert len(results["folds"]) == 3

    from collections import Counter

    validation_group_counts = Counter()
    validated_sample_count = 0

    for fold in results["folds"]:
        assert fold["group_overlap"] == []
        assert fold["train_size"] + fold["validation_size"] == len(features)
        assert (
            fold["train_group_count"] + fold["validation_group_count"]
            == len(set(groups))
        )
        assert len(fold["validation_groups"]) == fold["validation_group_count"]

        validation_group_counts.update(fold["validation_groups"])
        validated_sample_count += fold["validation_size"]

    assert validated_sample_count == len(features)
    assert set(validation_group_counts) == set(groups)
    assert all(count == 1 for count in validation_group_counts.values())


def test_grouped_cross_validation_rejects_mismatched_lengths():
    from ai.risk_prediction.cross_validation import (
        run_grouped_cross_validation,
    )

    features, labels, groups = build_grouped_test_dataset()

    try:
        run_grouped_cross_validation(
            MockRiskPredictionModel,
            features,
            labels,
            groups[:-1],
            n_splits=3,
        )
    except ValueError as error:
        assert "same number of samples" in str(error)
    else:
        raise AssertionError("Expected ValueError for mismatched lengths.")


def test_grouped_cross_validation_rejects_inconsistent_group_labels():
    from ai.risk_prediction.cross_validation import (
        run_grouped_cross_validation,
    )

    features, labels, groups = build_grouped_test_dataset()
    labels[1] = "medium"

    try:
        run_grouped_cross_validation(
            MockRiskPredictionModel,
            features,
            labels,
            groups,
            n_splits=3,
        )
    except ValueError as error:
        assert "single consistent label" in str(error)
    else:
        raise AssertionError("Expected ValueError for inconsistent group labels.")


def test_grouped_cross_validation_rejects_insufficient_groups_per_class():
    from ai.risk_prediction.cross_validation import (
        run_grouped_cross_validation,
    )

    features = [[float(index)] for index in range(9)]
    labels = (
        ["low"] * 3
        + ["critical"] * 3
        + ["critical"] * 3
    )
    groups = (
        ["low_1"] * 3
        + ["critical_1"] * 3
        + ["critical_2"] * 3
    )

    try:
        run_grouped_cross_validation(
            MockRiskPredictionModel,
            features,
            labels,
            groups,
            n_splits=3,
        )
    except ValueError as error:
        assert "distinct groups per class" in str(error)
    else:
        raise AssertionError("Expected ValueError for too few class groups.")
