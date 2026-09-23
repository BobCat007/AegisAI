from collections import Counter

import pytest

from ai.risk_prediction.dataset import (
    create_stratified_folds,
    split_dataset,
)


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


def test_split_dataset_preserves_sample_count():
    features, labels = build_test_dataset()

    (
        train_features,
        validation_features,
        test_features,
        train_labels,
        validation_labels,
        test_labels,
    ) = split_dataset(
        features,
        labels,
    )

    assert (
        len(train_features)
        + len(validation_features)
        + len(test_features)
        == len(features)
    )

    assert (
        len(train_labels)
        + len(validation_labels)
        + len(test_labels)
        == len(labels)
    )


def test_split_dataset_preserves_labels():
    features, labels = build_test_dataset()

    (
        _,
        _,
        _,
        train_labels,
        validation_labels,
        test_labels,
    ) = split_dataset(
        features,
        labels,
    )

    combined_labels = (
        train_labels
        + validation_labels
        + test_labels
    )

    assert Counter(combined_labels) == Counter(labels)


def test_split_dataset_is_reproducible():
    features, labels = build_test_dataset()

    first_split = split_dataset(
        features,
        labels,
        random_state=42,
    )

    second_split = split_dataset(
        features,
        labels,
        random_state=42,
    )

    assert first_split == second_split


def test_split_dataset_requires_matching_lengths():
    features = [[1.0], [2.0], [3.0]]
    labels = ["low", "medium"]

    with pytest.raises(
        ValueError,
        match="same number of samples",
    ):
        split_dataset(
            features,
            labels,
        )


def test_split_dataset_rejects_empty_dataset():
    with pytest.raises(
        ValueError,
        match="at least one sample",
    ):
        split_dataset(
            [],
            [],
        )


def test_split_dataset_rejects_invalid_split_sizes():
    features, labels = build_test_dataset()

    with pytest.raises(
        ValueError,
        match="test_size must be between 0 and 1",
    ):
        split_dataset(
            features,
            labels,
            test_size=1.0,
        )

    with pytest.raises(
        ValueError,
        match="validation_size must be between 0 and 1",
    ):
        split_dataset(
            features,
            labels,
            validation_size=1.0,
        )

    with pytest.raises(
        ValueError,
        match="less than 1",
    ):
        split_dataset(
            features,
            labels,
            test_size=0.6,
            validation_size=0.4,
        )


def test_split_dataset_requires_enough_samples_per_class():
    features = [[float(index)] for index in range(4)]
    labels = [
        "low",
        "low",
        "medium",
        "critical",
    ]

    with pytest.raises(
        ValueError,
        match="at least 2 samples per class",
    ):
        split_dataset(
            features,
            labels,
        )


def test_create_stratified_folds_returns_requested_number_of_folds():
    features, labels = build_test_dataset()

    folds = create_stratified_folds(
        features,
        labels,
        n_splits=3,
    )

    assert len(folds) == 3


def test_create_stratified_folds_cover_every_sample():
    features, labels = build_test_dataset()

    folds = create_stratified_folds(
        features,
        labels,
        n_splits=3,
    )

    validation_indices = []

    for _, fold_validation_indices in folds:
        validation_indices.extend(
            fold_validation_indices
        )

    assert sorted(validation_indices) == list(
        range(len(features))
    )


def test_create_stratified_folds_have_no_train_validation_overlap():
    features, labels = build_test_dataset()

    folds = create_stratified_folds(
        features,
        labels,
        n_splits=3,
    )

    for train_indices, validation_indices in folds:
        assert set(train_indices).isdisjoint(
            validation_indices
        )


def test_create_stratified_folds_preserve_class_presence():
    features, labels = build_test_dataset()

    folds = create_stratified_folds(
        features,
        labels,
        n_splits=3,
    )

    for _, validation_indices in folds:
        validation_labels = [
            labels[index]
            for index in validation_indices
        ]

        assert set(validation_labels) == {
            "low",
            "medium",
            "high",
            "critical",
        }


def test_create_stratified_folds_is_reproducible():
    features, labels = build_test_dataset()

    first_folds = create_stratified_folds(
        features,
        labels,
        n_splits=3,
        random_state=42,
    )

    second_folds = create_stratified_folds(
        features,
        labels,
        n_splits=3,
        random_state=42,
    )

    assert first_folds == second_folds


def test_create_stratified_folds_rejects_too_many_folds():
    features, labels = build_test_dataset()

    with pytest.raises(
        ValueError,
        match="cannot exceed",
    ):
        create_stratified_folds(
            features,
            labels,
            n_splits=5,
        )
