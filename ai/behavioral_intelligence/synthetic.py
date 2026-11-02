import random

from ai.behavioral_intelligence.models import BehavioralObservation


def generate_normal_observations(
    count: int = 500,
    *,
    random_state: int = 42,
) -> list[BehavioralObservation]:
    """
    Generate controlled synthetic baseline traffic.

    These observations are for testing the training and inference
    pipeline. They are not representative production traffic.
    """

    if count < 20:
        raise ValueError(
            "At least 20 synthetic observations are required."
        )

    rng = random.Random(random_state)
    observations = []

    for index in range(count):
        request_count = rng.randint(100, 300)

        client_error_count = rng.randint(0, 8)
        server_error_count = rng.randint(0, 3)

        observations.append(
            BehavioralObservation(
                endpoint_path=f"/api/resource/{index % 10}",
                method="GET",
                window_seconds=60,
                request_count=request_count,
                unique_identity_count=rng.randint(
                    1,
                    min(20, request_count),
                ),
                unique_client_count=rng.randint(
                    1,
                    min(15, request_count),
                ),
                client_error_count=client_error_count,
                server_error_count=server_error_count,
                auth_failure_count=rng.randint(
                    0,
                    client_error_count,
                ),
                mean_latency_ms=max(
                    1.0,
                    rng.gauss(80, 20),
                ),
                latency_stddev_ms=max(
                    0.0,
                    rng.gauss(20, 5),
                ),
                mean_response_size_bytes=max(
                    1.0,
                    rng.gauss(1500, 300),
                ),
                response_size_stddev_bytes=max(
                    0.0,
                    rng.gauss(200, 50),
                ),
                data_origin="synthetic",
            )
        )

    return observations
