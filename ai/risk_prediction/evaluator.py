from collections import Counter
from typing import Any

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def evaluate_predictions(
    actual_labels: list[str],
    predicted_labels: list[str],
) -> dict[str, Any]:
    """
    Calculate classification metrics for risk predictions.

    Returns overall accuracy, macro and weighted metrics, per-class
    metrics, and the confusion matrix.
    """

    if len(actual_labels) != len(predicted_labels):
        raise ValueError(
            "Actual and predicted labels must contain "
            "the same number of samples."
        )

    if not actual_labels:
        raise ValueError(
            "Evaluation requires at least one sample."
        )

    label_order = [
        "low",
        "medium",
        "high",
        "critical",
    ]

    return {
        "accuracy": float(
            accuracy_score(
                actual_labels,
                predicted_labels,
            )
        ),
        "precision_macro": float(
            precision_score(
                actual_labels,
                predicted_labels,
                labels=label_order,
                average="macro",
                zero_division=0,
            )
        ),
        "recall_macro": float(
            recall_score(
                actual_labels,
                predicted_labels,
                labels=label_order,
                average="macro",
                zero_division=0,
            )
        ),
        "f1_macro": float(
            f1_score(
                actual_labels,
                predicted_labels,
                labels=label_order,
                average="macro",
                zero_division=0,
            )
        ),
        "precision_weighted": float(
            precision_score(
                actual_labels,
                predicted_labels,
                labels=label_order,
                average="weighted",
                zero_division=0,
            )
        ),
        "recall_weighted": float(
            recall_score(
                actual_labels,
                predicted_labels,
                labels=label_order,
                average="weighted",
                zero_division=0,
            )
        ),
        "f1_weighted": float(
            f1_score(
                actual_labels,
                predicted_labels,
                labels=label_order,
                average="weighted",
                zero_division=0,
            )
        ),
        "classification_report": classification_report(
            actual_labels,
            predicted_labels,
            labels=label_order,
            zero_division=0,
            output_dict=True,
        ),
        "confusion_matrix": confusion_matrix(
            actual_labels,
            predicted_labels,
            labels=label_order,
        ).tolist(),
        "actual_distribution": dict(
            Counter(actual_labels)
        ),
        "predicted_distribution": dict(
            Counter(predicted_labels)
        ),
    }
