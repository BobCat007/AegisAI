from ai.risk_prediction.evaluator import evaluate_predictions


def test_evaluate_predictions_returns_expected_accuracy():
    actual = [
        "low",
        "low",
        "medium",
        "medium",
        "high",
        "critical",
    ]

    predicted = [
        "low",
        "medium",
        "medium",
        "medium",
        "high",
        "critical",
    ]

    metrics = evaluate_predictions(
        actual,
        predicted,
    )

    assert metrics["accuracy"] == 5 / 6


def test_evaluate_predictions_returns_all_overall_metrics():
    actual = [
        "low",
        "medium",
        "high",
        "critical",
    ]

    predicted = [
        "low",
        "medium",
        "high",
        "critical",
    ]

    metrics = evaluate_predictions(
        actual,
        predicted,
    )

    assert metrics["accuracy"] == 1.0
    assert metrics["precision_macro"] == 1.0
    assert metrics["recall_macro"] == 1.0
    assert metrics["f1_macro"] == 1.0
    assert metrics["precision_weighted"] == 1.0
    assert metrics["recall_weighted"] == 1.0
    assert metrics["f1_weighted"] == 1.0


def test_evaluate_predictions_returns_per_class_metrics():
    actual = [
        "low",
        "low",
        "medium",
        "high",
        "critical",
    ]

    predicted = [
        "low",
        "medium",
        "medium",
        "high",
        "critical",
    ]

    metrics = evaluate_predictions(
        actual,
        predicted,
    )

    report = metrics["classification_report"]

    assert "low" in report
    assert "medium" in report
    assert "high" in report
    assert "critical" in report

    assert report["low"]["recall"] == 0.5
    assert report["medium"]["recall"] == 1.0
    assert report["high"]["recall"] == 1.0
    assert report["critical"]["recall"] == 1.0


def test_evaluate_predictions_returns_confusion_matrix():
    actual = [
        "low",
        "medium",
        "high",
        "critical",
    ]

    predicted = [
        "low",
        "medium",
        "high",
        "critical",
    ]

    metrics = evaluate_predictions(
        actual,
        predicted,
    )

    assert metrics["confusion_matrix"] == [
        [1, 0, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1],
    ]


def test_evaluate_predictions_returns_class_distributions():
    actual = [
        "low",
        "low",
        "medium",
        "high",
        "critical",
    ]

    predicted = [
        "low",
        "medium",
        "medium",
        "high",
        "critical",
    ]

    metrics = evaluate_predictions(
        actual,
        predicted,
    )

    assert metrics["actual_distribution"] == {
        "low": 2,
        "medium": 1,
        "high": 1,
        "critical": 1,
    }

    assert metrics["predicted_distribution"] == {
        "low": 1,
        "medium": 2,
        "high": 1,
        "critical": 1,
    }


def test_evaluate_predictions_rejects_mismatched_lengths():
    actual = [
        "low",
        "medium",
    ]

    predicted = [
        "low",
    ]

    try:
        evaluate_predictions(
            actual,
            predicted,
        )
    except ValueError as error:
        assert str(error) == (
            "Actual and predicted labels must contain "
            "the same number of samples."
        )
    else:
        raise AssertionError(
            "Expected ValueError for mismatched label lengths."
        )


def test_evaluate_predictions_rejects_empty_input():
    try:
        evaluate_predictions(
            [],
            [],
        )
    except ValueError as error:
        assert str(error) == (
            "Evaluation requires at least one sample."
        )
    else:
        raise AssertionError(
            "Expected ValueError for empty evaluation input."
        )
