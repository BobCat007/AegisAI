import csv
from pathlib import Path

from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES


EXPECTED_COLUMNS = (
    *SECURITY_CONTEXT_FEATURE_NAMES,
    "risk_label",
    "graph_context_score",
)

EXPECTED_COLUMNS_WITH_ENDPOINT_ID = (
    "endpoint_id",
    *EXPECTED_COLUMNS,
)


def _load_dataset(
    path: str | Path,
    require_endpoint_ids: bool = False,
) -> tuple[list[list[float]], list[str], list[str]]:
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
        has_endpoint_ids = (
            actual_columns == EXPECTED_COLUMNS_WITH_ENDPOINT_ID
        )

        if not has_endpoint_ids and actual_columns != EXPECTED_COLUMNS:
            raise ValueError(
                "Training dataset schema does not match the "
                "expected security-context schema. "
                f"Expected {len(EXPECTED_COLUMNS_WITH_ENDPOINT_ID)} "
                f"columns with endpoint IDs, got {len(actual_columns)}."
            )

        if require_endpoint_ids and not has_endpoint_ids:
            raise ValueError(
                "Training dataset must contain an endpoint_id column "
                "for grouped cross-validation."
            )

        features: list[list[float]] = []
        labels: list[str] = []
        endpoint_ids: list[str] = []

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

            if has_endpoint_ids:
                endpoint_id = row["endpoint_id"]

                if not endpoint_id or not endpoint_id.strip():
                    raise ValueError(
                        "Missing endpoint_id in training dataset "
                        f"at row {row_number}."
                    )

                endpoint_ids.append(endpoint_id)

            features.append(feature_vector)
            labels.append(risk_label)

    if not features:
        raise ValueError(
            "Training dataset must contain at least one sample."
        )

    return features, labels, endpoint_ids


def load_graph_training_dataset(
    path: str | Path,
) -> tuple[list[list[float]], list[str]]:
    """
    Load the graph-aware training dataset.

    Preserves the existing two-value return interface.
    """
    features, labels, _ = _load_dataset(path)
    return features, labels


def load_graph_training_dataset_with_endpoint_ids(
    path: str | Path,
) -> tuple[list[list[float]], list[str], list[str]]:
    """
    Load features, labels, and explicit endpoint IDs.

    Endpoint IDs are used as groups during cross-validation
    to prevent samples from the same endpoint appearing in
    both training and validation folds.
    """
    return _load_dataset(path, require_endpoint_ids=True)
