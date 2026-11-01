
from pathlib import Path
import csv

import pytest

from ai.risk_prediction.data_loader import (
    EXPECTED_COLUMNS,
    EXPECTED_COLUMNS_WITH_ENDPOINT_ID,
    load_graph_training_dataset,
    load_graph_training_dataset_with_endpoint_ids,
)
from ai.security_context_schema import (
    SECURITY_CONTEXT_FEATURE_NAMES,
)


def write_dataset(
    path: Path,
    header: list[str],
    rows: list[list[str]],
) -> None:
    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(header)
        writer.writerows(rows)


def test_load_graph_training_dataset_returns_expected_shape(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS)

    row = ["0.0" for _ in SECURITY_CONTEXT_FEATURE_NAMES] + [
        "low",
        "20.0",
    ]

    write_dataset(dataset_path, header, [row])

    features, labels = load_graph_training_dataset(dataset_path)

    assert len(features) == 1
    assert len(features[0]) == 31
    assert labels == ["low"]


def test_loader_excludes_graph_context_score_from_features(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS)

    row = ["1.0" for _ in SECURITY_CONTEXT_FEATURE_NAMES] + [
        "high",
        "100.0",
    ]

    write_dataset(dataset_path, header, [row])

    features, labels = load_graph_training_dataset(dataset_path)

    assert features == [[1.0] * 31]
    assert labels == ["high"]


def test_loader_accepts_all_risk_labels(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS)
    rows = []

    for label in ["low", "medium", "high", "critical"]:
        rows.append(
            ["0.0" for _ in SECURITY_CONTEXT_FEATURE_NAMES]
            + [label, "30.0"]
        )

    write_dataset(dataset_path, header, rows)

    features, labels = load_graph_training_dataset(dataset_path)

    assert len(features) == 4
    assert labels == ["low", "medium", "high", "critical"]


def test_loader_rejects_missing_dataset(tmp_path):
    dataset_path = tmp_path / "missing.csv"

    with pytest.raises(
        FileNotFoundError,
        match="Training dataset not found",
    ):
        load_graph_training_dataset(dataset_path)


def test_loader_rejects_invalid_schema(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS)
    header[-1] = "unexpected_column"

    row = ["0.0" for _ in SECURITY_CONTEXT_FEATURE_NAMES] + [
        "low",
        "20.0",
    ]

    write_dataset(dataset_path, header, [row])

    with pytest.raises(
        ValueError,
        match="Training dataset schema does not match",
    ):
        load_graph_training_dataset(dataset_path)


def test_loader_rejects_invalid_feature_value(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS)

    row = ["not-a-number" for _ in SECURITY_CONTEXT_FEATURE_NAMES] + [
        "low",
        "20.0",
    ]

    write_dataset(dataset_path, header, [row])

    with pytest.raises(
        ValueError,
        match="Invalid feature value",
    ):
        load_graph_training_dataset(dataset_path)


def test_loader_rejects_invalid_risk_label(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS)

    row = ["0.0" for _ in SECURITY_CONTEXT_FEATURE_NAMES] + [
        "unknown",
        "20.0",
    ]

    write_dataset(dataset_path, header, [row])

    with pytest.raises(
        ValueError,
        match="Invalid risk_label",
    ):
        load_graph_training_dataset(dataset_path)


def test_loader_rejects_empty_dataset(tmp_path):
    dataset_path = tmp_path / "training.csv"

    write_dataset(
        dataset_path,
        list(EXPECTED_COLUMNS),
        [],
    )

    with pytest.raises(
        ValueError,
        match="Training dataset must contain at least one sample",
    ):
        load_graph_training_dataset(dataset_path)


def test_loader_returns_explicit_endpoint_ids(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS_WITH_ENDPOINT_ID)

    rows = [
        ["endpoint_0"] + ["0.0"] * 31 + ["low", "20.0"],
        ["endpoint_0"] + ["1.0"] * 31 + ["medium", "30.0"],
        ["endpoint_1"] + ["2.0"] * 31 + ["high", "40.0"],
    ]

    write_dataset(dataset_path, header, rows)

    features, labels, endpoint_ids = (
        load_graph_training_dataset_with_endpoint_ids(dataset_path)
    )

    assert len(features) == 3
    assert len(features[0]) == 31
    assert labels == ["low", "medium", "high"]
    assert endpoint_ids == [
        "endpoint_0",
        "endpoint_0",
        "endpoint_1",
    ]


def test_loader_rejects_missing_endpoint_id(tmp_path):
    dataset_path = tmp_path / "training.csv"

    header = list(EXPECTED_COLUMNS_WITH_ENDPOINT_ID)
    row = [""] + ["0.0"] * 31 + ["low", "20.0"]

    write_dataset(dataset_path, header, [row])

    with pytest.raises(
        ValueError,
        match="Missing endpoint_id",
    ):
        load_graph_training_dataset_with_endpoint_ids(dataset_path)


def test_endpoint_id_loader_rejects_legacy_schema(tmp_path):
    dataset_path = tmp_path / "training.csv"

    row = ["0.0"] * 31 + ["low", "20.0"]

    write_dataset(
        dataset_path,
        list(EXPECTED_COLUMNS),
        [row],
    )

    with pytest.raises(
        ValueError,
        match="must contain an endpoint_id column",
    ):
        load_graph_training_dataset_with_endpoint_ids(dataset_path)
