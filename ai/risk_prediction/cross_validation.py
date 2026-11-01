
from statistics import pstdev
from typing import Any

from ai.risk_prediction.dataset import create_stratified_folds
from ai.risk_prediction.evaluator import evaluate_predictions
from ai.risk_prediction.model import RiskPredictionModel


def _calculate_fold_metric_summary(
    fold_results: list[dict[str, Any]],
) -> dict[str, float]:
    """Calculate mean and population standard deviation across folds."""

    if not fold_results:
        raise ValueError("At least one fold result is required.")

    metric_names = {
        "accuracy": "accuracy",
        "precision_macro": "precision_macro",
        "recall_macro": "recall_macro",
        "f1_macro": "f1_macro",
    }

    summary: dict[str, float] = {}

    for output_name, metric_name in metric_names.items():
        values = [
            fold["metrics"][metric_name]
            for fold in fold_results
        ]

        summary[f"mean_{output_name}"] = sum(values) / len(values)
        summary[f"std_{output_name}"] = pstdev(values)

    return summary


def run_stratified_cross_validation(
    model_factory,
    features: list[list[float]],
    labels: list[str],
    *,
    n_splits: int = 3,
    random_state: int = 42,
) -> dict[str, Any]:
    """
    Train and evaluate a risk prediction model using stratified
    cross-validation.

    A fresh model instance is created for every fold so that no
    learned state leaks between folds.

    Returns per-fold metrics, mean metrics, and standard deviations.
    """

    folds = create_stratified_folds(
        features,
        labels,
        n_splits=n_splits,
        random_state=random_state,
    )

    fold_results: list[dict[str, Any]] = []

    for fold_number, (train_indices, validation_indices) in enumerate(
        folds,
        start=1,
    ):
        train_features = [
            features[index]
            for index in train_indices
        ]

        train_labels = [
            labels[index]
            for index in train_indices
        ]

        validation_features = [
            features[index]
            for index in validation_indices
        ]

        validation_labels = [
            labels[index]
            for index in validation_indices
        ]

        model = model_factory()

        if not isinstance(model, RiskPredictionModel):
            raise TypeError(
                "model_factory must return a RiskPredictionModel."
            )

        model.fit(
            train_features,
            train_labels,
        )

        predictions = model.predict(
            validation_features,
        )

        metrics = evaluate_predictions(
            validation_labels,
            predictions,
        )

        fold_results.append(
            {
                "fold": fold_number,
                "train_size": len(train_features),
                "validation_size": len(validation_features),
                "metrics": metrics,
            }
        )

    return {
        "n_splits": n_splits,
        "folds": fold_results,
        **_calculate_fold_metric_summary(fold_results),
    }


def run_grouped_cross_validation(
    model_factory,
    features: list[list[float]],
    labels: list[str],
    groups: list[str],
    *,
    n_splits: int = 3,
    random_state: int = 42,
) -> dict[str, Any]:
    """
    Evaluate a model while keeping each endpoint group in one fold.

    Returns per-fold metrics, mean metrics, and population standard
    deviations across folds.
    """
    from collections import Counter

    from sklearn.model_selection import StratifiedGroupKFold

    if not features:
        raise ValueError("Dataset must contain at least one sample.")

    if len(features) != len(labels) or len(features) != len(groups):
        raise ValueError(
            "Features, labels, and groups must contain the same "
            "number of samples."
        )

    if n_splits < 2:
        raise ValueError("n_splits must be at least 2.")

    unique_groups = set(groups)

    if len(unique_groups) < n_splits:
        raise ValueError(
            "n_splits cannot exceed the number of unique groups."
        )

    # Each endpoint group must have one consistent baseline label.
    labels_by_group: dict[str, set[str]] = {}

    for group, label in zip(groups, labels):
        labels_by_group.setdefault(group, set()).add(label)

    inconsistent_groups = [
        group
        for group, group_labels in labels_by_group.items()
        if len(group_labels) != 1
    ]

    if inconsistent_groups:
        raise ValueError(
            "Every group must have a single consistent label. "
            f"Inconsistent groups: {inconsistent_groups}"
        )

    # Group-level class counts matter more than row counts here.
    group_label_counts = Counter(
        next(iter(group_labels))
        for group_labels in labels_by_group.values()
    )

    if min(group_label_counts.values()) < n_splits:
        raise ValueError(
            "Grouped stratification requires at least n_splits "
            "distinct groups per class. "
            f"Group counts by class: {dict(group_label_counts)}"
        )

    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )

    fold_results: list[dict[str, Any]] = []

    for fold_number, (train_indices, validation_indices) in enumerate(
        splitter.split(features, labels, groups),
        start=1,
    ):
        train_groups = {
            groups[index]
            for index in train_indices
        }

        validation_groups = {
            groups[index]
            for index in validation_indices
        }

        if train_groups & validation_groups:
            raise RuntimeError(
                f"Group leakage detected in fold {fold_number}."
            )

        train_features = [
            features[index]
            for index in train_indices
        ]

        train_labels = [
            labels[index]
            for index in train_indices
        ]

        validation_features = [
            features[index]
            for index in validation_indices
        ]

        validation_labels = [
            labels[index]
            for index in validation_indices
        ]

        model = model_factory()

        if not isinstance(model, RiskPredictionModel):
            raise TypeError(
                "model_factory must return a RiskPredictionModel."
            )

        model.fit(train_features, train_labels)
        predictions = model.predict(validation_features)

        metrics = evaluate_predictions(
            validation_labels,
            predictions,
        )

        fold_results.append(
            {
                "fold": fold_number,
                "train_size": len(train_indices),
                "validation_size": len(validation_indices),
                "train_group_count": len(train_groups),
                "validation_group_count": len(validation_groups),
                "validation_groups": sorted(validation_groups),
                "group_overlap": sorted(train_groups & validation_groups),
                "metrics": metrics,
            }
        )

    return {
        "n_splits": n_splits,
        "sample_count": len(features),
        "group_count": len(unique_groups),
        "folds": fold_results,
        **_calculate_fold_metric_summary(fold_results),
    }
