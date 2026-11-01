
from collections import Counter
from pathlib import Path

from scripts.generate_graph_scenarios import build_graph_scenarios
from scripts.generate_training_data import generate_endpoint_templates
from ai.risk_prediction.cross_validation import run_grouped_cross_validation
from ai.risk_prediction.data_loader import (
    load_graph_training_dataset_with_endpoint_ids,
)
from ai.risk_prediction.xgboost_model import XGBoostRiskPredictionModel


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "api_graph_training_data.csv"
)


def main() -> None:
    features, labels, groups = (
        load_graph_training_dataset_with_endpoint_ids(DATASET_PATH)
    )

    endpoints = generate_endpoint_templates()
    scenarios = build_graph_scenarios()

    expected_samples = len(endpoints) * len(scenarios)

    if len(features) != expected_samples:
        raise ValueError(
            f"Dataset has {len(features)} samples, but the endpoint "
            f"generator and graph scenarios imply {expected_samples}. "
            "Regenerate the dataset."
        )

    if len(labels) != len(features) or len(groups) != len(features):
        raise ValueError(
            "Features, labels, and endpoint IDs must have equal lengths."
        )

    if any(not endpoint_id.strip() for endpoint_id in groups):
        raise ValueError("Dataset contains missing endpoint IDs.")

    group_counts = Counter(groups)

    if len(group_counts) != len(endpoints):
        raise ValueError(
            f"Expected {len(endpoints)} endpoint groups, "
            f"but found {len(group_counts)}."
        )

    incorrect_groups = {
        endpoint_id: count
        for endpoint_id, count in group_counts.items()
        if count != len(scenarios)
    }

    if incorrect_groups:
        raise ValueError(
            "Each endpoint must have exactly "
            f"{len(scenarios)} scenario samples. "
            f"Invalid groups: {incorrect_groups}"
        )

    results = run_grouped_cross_validation(
        XGBoostRiskPredictionModel,
        features,
        labels,
        groups,
        n_splits=3,
        random_state=42,
    )

    print("GROUPED CROSS-VALIDATION")
    print(f"Samples: {results['sample_count']}")
    print(f"Endpoint groups: {results['group_count']}")
    print(f"Scenarios per endpoint: {len(scenarios)}")
    print(f"Folds: {results['n_splits']}")

    print(
        f"Mean accuracy: {results['mean_accuracy']:.4f} "
        f"+/- {results['std_accuracy']:.4f}"
    )

    print(
        f"Mean macro precision: {results['mean_precision_macro']:.4f} "
        f"+/- {results['std_precision_macro']:.4f}"
    )

    print(
        f"Mean macro recall: {results['mean_recall_macro']:.4f} "
        f"+/- {results['std_recall_macro']:.4f}"
    )

    print(
        f"Mean macro F1: {results['mean_f1_macro']:.4f} "
        f"+/- {results['std_f1_macro']:.4f}"
    )

    print("\nFOLD DETAILS")

    for fold in results["folds"]:
        metrics = fold["metrics"]

        print(
            f"Fold {fold['fold']}: "
            f"train={fold['train_size']} samples/"
            f"{fold['train_group_count']} groups, "
            f"validation={fold['validation_size']} samples/"
            f"{fold['validation_group_count']} groups, "
            f"accuracy={metrics['accuracy']:.4f}, "
            f"macro_f1={metrics['f1_macro']:.4f}, "
            f"group_overlap={fold['group_overlap']}"
        )


if __name__ == "__main__":
    main()
