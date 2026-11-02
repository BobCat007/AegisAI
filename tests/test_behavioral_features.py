import pytest

from ai.behavioral_intelligence.features import (
    BEHAVIORAL_FEATURE_NAMES,
    extract_behavioral_features,
)
from ai.behavioral_intelligence.models import BehavioralObservation


def build_observation(**overrides):
    values = {
        "endpoint_path": "/api/users",
        "method": "GET",
        "window_seconds": 60,
        "request_count": 100,
        "unique_identity_count": 10,
        "unique_client_count": 5,
        "client_error_count": 4,
        "server_error_count": 1,
        "auth_failure_count": 2,
        "mean_latency_ms": 80,
        "latency_stddev_ms": 20,
        "mean_response_size_bytes": 1500,
        "response_size_stddev_bytes": 200,
        "data_origin": "runtime",
    }
    values.update(overrides)
    return BehavioralObservation(**values)


def test_behavioral_feature_vector_matches_schema():
    observation = build_observation()

    features = extract_behavioral_features(observation)

    assert len(features) == len(BEHAVIORAL_FEATURE_NAMES)
    assert features[0] == pytest.approx(100 / 60)
    assert features[1] == pytest.approx(0.1)
    assert features[2] == pytest.approx(0.05)
    assert features[3] == pytest.approx(0.04)
    assert features[4] == pytest.approx(0.01)
    assert features[5] == pytest.approx(0.02)


def test_behavioral_feature_schema_has_ten_features():
    assert len(BEHAVIORAL_FEATURE_NAMES) == 10


def test_rejects_identity_count_above_request_count():
    observation = build_observation(
        unique_identity_count=101,
    )

    with pytest.raises(ValueError, match="unique_identity_count"):
        extract_behavioral_features(observation)


def test_rejects_error_counts_above_request_count():
    observation = build_observation(
        client_error_count=80,
        server_error_count=30,
        auth_failure_count=10,
    )

    with pytest.raises(ValueError, match="error counts"):
        extract_behavioral_features(observation)


def test_rejects_authentication_failures_above_client_errors():
    observation = build_observation(
        client_error_count=2,
        auth_failure_count=5,
    )

    with pytest.raises(ValueError, match="auth_failure_count"):
        extract_behavioral_features(observation)


def test_rejects_extra_observation_fields():
    values = {
        "endpoint_path": "/api/users",
        "method": "GET",
        "window_seconds": 60,
        "request_count": 100,
        "unique_identity_count": 10,
        "unique_client_count": 5,
        "client_error_count": 4,
        "server_error_count": 1,
        "auth_failure_count": 2,
        "mean_latency_ms": 80,
        "latency_stddev_ms": 20,
        "mean_response_size_bytes": 1500,
        "response_size_stddev_bytes": 200,
        "unexpected_field": "not allowed",
    }

    with pytest.raises(ValueError):
        BehavioralObservation(**values)
