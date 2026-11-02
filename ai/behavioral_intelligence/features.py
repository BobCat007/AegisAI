from ai.behavioral_intelligence.models import BehavioralObservation


BEHAVIORAL_FEATURE_NAMES = (
    "request_rate_per_second",
    "unique_identity_ratio",
    "unique_client_ratio",
    "client_error_rate",
    "server_error_rate",
    "auth_failure_rate",
    "mean_latency_ms",
    "latency_stddev_ms",
    "mean_response_size_bytes",
    "response_size_stddev_bytes",
)


def extract_behavioral_features(
    observation: BehavioralObservation,
) -> list[float]:
    """
    Convert an aggregated API observation into a numeric feature vector.

    Ratios are normalized by request count. Raw latency and response-size
    measurements are retained for behavioral analysis.
    """

    requests = observation.request_count

    if observation.unique_identity_count > requests:
        raise ValueError(
            "unique_identity_count cannot exceed request_count."
        )

    if observation.unique_client_count > requests:
        raise ValueError(
            "unique_client_count cannot exceed request_count."
        )

    if observation.client_error_count > requests:
        raise ValueError(
            "client_error_count cannot exceed request_count."
        )

    if observation.server_error_count > requests:
        raise ValueError(
            "server_error_count cannot exceed request_count."
        )

    if (
        observation.client_error_count
        + observation.server_error_count
        > requests
    ):
        raise ValueError(
            "Client and server error counts cannot exceed request_count."
        )

    if observation.auth_failure_count > observation.client_error_count:
        raise ValueError(
            "auth_failure_count cannot exceed client_error_count."
        )

    return [
        requests / observation.window_seconds,
        observation.unique_identity_count / requests,
        observation.unique_client_count / requests,
        observation.client_error_count / requests,
        observation.server_error_count / requests,
        observation.auth_failure_count / requests,
        observation.mean_latency_ms,
        observation.latency_stddev_ms,
        observation.mean_response_size_bytes,
        observation.response_size_stddev_bytes,
    ]
