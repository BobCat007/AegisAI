import csv
from pathlib import Path

from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES


EXPECTED_COLUMNS = (
    *SECURITY_CONTEXT_FEATURE_NAMES,
    "risk_label",
    "graph_context_score",
)


def load_graph_training_dataset(
    path: str | Path,
) -> tuple[list[list[float]], list[str]]:
    """
    Load the graph-aware security training dataset.

    Returns:
        features:
            The 31 security-context features used by the
            risk prediction model.

        labels:
            The risk_label classification target.

    The graph_context_score column is intentionally excluded
    from the model features because it is derived from the
    same risk logic used to construct the training labels.
    """
    dataset_path = Path(path)

    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Training dataset not found: {dataset_path}"
        )

    with dataset_path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        if reader.fieldnames is None:
            raise ValueError(
                "Training dataset must contain a header row."
            )

        actual_columns = tuple(reader.fieldnames)

        if actual_columns != EXPECTED_COLUMNS:
            raise ValueError(
                "Training dataset schema does not match the "
                "expected security-context schema. "
                f"Expected {len(EXPECTED_COLUMNS)} columns, "
                f"got {len(actual_columns)}."
            )

        features: list[list[float]] = []
        labels: list[str] = []

        for row_number, row in enumerate(reader, start=2):
            try:
                feature_vector = [
                    float(row[name])
                    for name in SECURITY_CONTEXT_FEATURE_NAMES
                ]
            except (TypeError, ValueError) as error:
                raise ValueError(
                    "Invalid feature value in training dataset "
                    f"at row {row_number}."
                ) from error

            risk_label = row["risk_label"]

            if risk_label not in {
                "low",
                "medium",
                "high",
                "critical",
            }:
                raise ValueError(
                    "Invalid risk_label in training dataset "
                    f"at row {row_number}: {risk_label!r}"
                )

            features.append(feature_vector)
            labels.append(risk_label)

    if not features:
        raise ValueError(
            "Training dataset must contain at least one sample."
        )

    return features, labels
