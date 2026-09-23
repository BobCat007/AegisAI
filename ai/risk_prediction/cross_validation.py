from typing import Any

from ai.risk_prediction.dataset import create_stratified_folds
from ai.risk_prediction.evaluator import evaluate_predictions
from ai.risk_prediction.model import RiskPredictionModel


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

    Returns per-fold metrics together with averaged overall metrics.
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

    accuracies = [
        result["metrics"]["accuracy"]
        for result in fold_results
    ]

    precision_macro = [
        result["metrics"]["precision_macro"]
        for result in fold_results
    ]

    recall_macro = [
        result["metrics"]["recall_macro"]
        for result in fold_results
    ]

    f1_macro = [
        result["metrics"]["f1_macro"]
        for result in fold_results
    ]

    return {
        "n_splits": n_splits,
        "folds": fold_results,
        "mean_accuracy": sum(accuracies) / len(accuracies),
        "mean_precision_macro": (
            sum(precision_macro)
            / len(precision_macro)
        ),
        "mean_recall_macro": (
            sum(recall_macro)
            / len(recall_macro)
        ),
        "mean_f1_macro": (
            sum(f1_macro)
            / len(f1_macro)
        ),
    }
