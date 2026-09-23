from collections import Counter

from sklearn.model_selection import StratifiedKFold, train_test_split


def split_dataset(
    features: list[list[float]],
    labels: list[str],
    *,
    test_size: float = 0.2,
    validation_size: float = 0.2,
    random_state: int = 42,
) -> tuple[
    list[list[float]],
    list[list[float]],
    list[list[float]],
    list[str],
    list[str],
    list[str],
]:
    """
    Split features and labels into train, validation, and test sets.

    Both validation and test sets are created with stratification so that
    class proportions are preserved as closely as the requested split
    sizes allow.

    Every class must contain enough samples for the requested three-way
    split. This prevents a minority class from disappearing from one of
    the evaluation sets.
    """

    if len(features) != len(labels):
        raise ValueError(
            "Features and labels must contain the same number of samples."
        )

    if not features:
        raise ValueError(
            "Dataset must contain at least one sample."
        )

    if not 0 < test_size < 1:
        raise ValueError(
            "test_size must be between 0 and 1."
        )

    if not 0 < validation_size < 1:
        raise ValueError(
            "validation_size must be between 0 and 1."
        )

    if test_size + validation_size >= 1:
        raise ValueError(
            "test_size + validation_size must be less than 1."
        )

    class_counts = Counter(labels)

    classes_with_too_few_samples = [
        label
        for label, count in class_counts.items()
        if count < 2
    ]

    if classes_with_too_few_samples:
        raise ValueError(
            "Stratified splitting requires at least 2 samples per class. "
            f"Classes with too few samples: "
            f"{sorted(classes_with_too_few_samples)}"
        )

    (
        train_features,
        temporary_features,
        train_labels,
        temporary_labels,
    ) = train_test_split(
        features,
        labels,
        test_size=test_size + validation_size,
        random_state=random_state,
        stratify=labels,
    )

    relative_validation_size = (
        validation_size
        / (test_size + validation_size)
    )

    temporary_class_counts = Counter(temporary_labels)

    if min(temporary_class_counts.values()) < 2:
        raise ValueError(
            "The requested train, validation, and test sizes "
            "cannot preserve every class in both evaluation sets. "
            "Provide more samples per class or adjust the split sizes."
        )

    (
        validation_features,
        test_features,
        validation_labels,
        test_labels,
    ) = train_test_split(
        temporary_features,
        temporary_labels,
        test_size=1.0 - relative_validation_size,
        random_state=random_state,
        stratify=temporary_labels,
    )

    return (
        train_features,
        validation_features,
        test_features,
        train_labels,
        validation_labels,
        test_labels,
    )


def create_stratified_folds(
    features: list[list[float]],
    labels: list[str],
    *,
    n_splits: int = 3,
    random_state: int = 42,
) -> list[tuple[list[int], list[int]]]:
    """
    Create stratified cross-validation folds.

    Returns a list of (train_indices, validation_indices) pairs.

    The number of folds cannot exceed the number of samples in the
    smallest class because every validation fold must contain
    representatives of every class.
    """

    if len(features) != len(labels):
        raise ValueError(
            "Features and labels must contain the same number of samples."
        )

    if not features:
        raise ValueError(
            "Dataset must contain at least one sample."
        )

    if n_splits < 2:
        raise ValueError(
            "n_splits must be at least 2."
        )

    class_counts = Counter(labels)
    minimum_class_count = min(class_counts.values())

    if n_splits > minimum_class_count:
        raise ValueError(
            "n_splits cannot exceed the number of samples "
            "in the smallest class. "
            f"Smallest class has {minimum_class_count} samples."
        )

    splitter = StratifiedKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )

    return [
        (train_indices.tolist(), validation_indices.tolist())
        for train_indices, validation_indices in splitter.split(
            features,
            labels,
        )
    ]
