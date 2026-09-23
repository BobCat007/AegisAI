from pathlib import Path

from ai.risk_prediction.cross_validation import (
    run_stratified_cross_validation,
)
from ai.risk_prediction.data_loader import (
    load_graph_training_dataset,
)
from ai.risk_prediction.xgboost_model import (
    XGBoostRiskPredictionModel,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "api_graph_training_data.csv"
)


def run_experiment() -> dict:
    """
    Run stratified cross-validation for the graph-aware
    XGBoost risk prediction model.
    """
    features, labels = load_graph_training_dataset(
        DATASET_PATH
    )

    results = run_stratified_cross_validation(
        XGBoostRiskPredictionModel,
        features,
        labels,
        n_splits=3,
        random_state=42,
    )

    return results


def main() -> None:
    features, labels = load_graph_training_dataset(
        DATASET_PATH
    )

    results = run_stratified_cross_validation(
        XGBoostRiskPredictionModel,
        features,
        labels,
        n_splits=3,
        random_state=42,
    )

    validation_sample_count = sum(
        fold["validation_size"]
        for fold in results["folds"]
    )

    print(
        f"Samples: {len(features)}"
    )
    print(
        f"Features per sample: {len(features[0])}"
    )
    print(
        f"Cross-validation folds: {results['n_splits']}"
    )
    print(
        f"Validation samples across folds: "
        f"{validation_sample_count}"
    )
    print(
        f"Mean accuracy: "
        f"{results['mean_accuracy']:.4f}"
    )
    print(
        f"Mean macro precision: "
        f"{results['mean_precision_macro']:.4f}"
    )
    print(
        f"Mean macro recall: "
        f"{results['mean_recall_macro']:.4f}"
    )
    print(
        f"Mean macro F1: "
        f"{results['mean_f1_macro']:.4f}"
    )

    for fold in results["folds"]:
        metrics = fold["metrics"]

        print(
            f"Fold {fold['fold']}: "
            f"accuracy={metrics['accuracy']:.4f}, "
            f"macro_f1={metrics['f1_macro']:.4f}"
        )


if __name__ == "__main__":
    main()
