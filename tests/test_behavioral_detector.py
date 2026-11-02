import pytest

from ai.behavioral_intelligence import (
    BehavioralObservation,
    IsolationForestBehavioralDetector,
)
from ai.behavioral_intelligence.synthetic import (
    generate_normal_observations,
)


def build_extreme_observation():
    return BehavioralObservation(
        endpoint_path="/api/admin/export",
        method="POST",
        window_seconds=60,
        request_count=10000,
        unique_identity_count=9000,
        unique_client_count=8000,
        client_error_count=5000,
        server_error_count=1000,
        auth_failure_count=4500,
        mean_latency_ms=5000,
        latency_stddev_ms=2500,
        mean_response_size_bytes=500000,
        response_size_stddev_bytes=200000,
        data_origin="synthetic",
    )


def test_detector_requires_training_before_prediction():
    detector = IsolationForestBehavioralDetector()

    with pytest.raises(RuntimeError, match="not been fitted"):
        detector.predict([build_extreme_observation()])


def test_detector_requires_at_least_twenty_training_observations():
    detector = IsolationForestBehavioralDetector()

    with pytest.raises(ValueError, match="At least 20"):
        detector.fit(
            generate_normal_observations(count=10)
        )


def test_detector_fits_and_predicts_observations():
    training = generate_normal_observations(count=300)

    detector = IsolationForestBehavioralDetector()
    detector.fit(training)

    results = detector.predict(
        [
            training[0],
            build_extreme_observation(),
        ]
    )

    assert len(results) == 2

    assert results[0].classification in {
        "normal",
        "anomalous",
    }

    assert results[1].classification == "anomalous"


def test_anomaly_result_contains_behavioral_signals():
    training = generate_normal_observations(count=300)

    detector = IsolationForestBehavioralDetector()
    detector.fit(training)

    result = detector.predict(
        [build_extreme_observation()]
    )[0]

    assert result.classification == "anomalous"
    assert result.anomaly_score > 0
    assert len(result.signals) > 0
    assert result.signals[0].feature_name
    assert result.signals[0].direction in {
        "above_baseline",
        "below_baseline",
    }


def test_detector_model_persistence(tmp_path):
    training = generate_normal_observations(count=300)

    detector = IsolationForestBehavioralDetector()
    detector.fit(training)

    artifact = tmp_path / "behavioral_model.joblib"
    detector.save(artifact)

    loaded = IsolationForestBehavioralDetector.load(artifact)

    original_result = detector.predict(
        [build_extreme_observation()]
    )

    loaded_result = loaded.predict(
        [build_extreme_observation()]
    )

    assert (
        original_result[0].classification
        == loaded_result[0].classification
    )

    assert (
        original_result[0].anomaly_score
        == pytest.approx(
            loaded_result[0].anomaly_score
        )
    )


def test_detector_rejects_missing_artifact(tmp_path):
    with pytest.raises(FileNotFoundError):
        IsolationForestBehavioralDetector.load(
            tmp_path / "missing.joblib"
        )
