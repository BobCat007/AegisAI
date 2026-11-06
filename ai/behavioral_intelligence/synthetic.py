import random
import statistics

from ai.behavioral_intelligence.models import BehavioralObservation


def generate_normal_observations(
    count: int = 500,
    *,
    random_state: int = 42,
) -> list[BehavioralObservation]:
    """
    Generate controlled synthetic observations resembling the
    normal traffic produced by tools.telemetry_sender.

    This is a runtime-shaped synthetic baseline, not production data.
    """

    if count < 20:
        raise ValueError(
            "At least 20 synthetic observations are required."
        )

    rng = random.Random(random_state)
    observations = []

    endpoints = [
        "/api/users",
        "/api/products",
        "/api/orders",
    ]
    methods = ["GET", "GET", "POST"]
    batch_sizes = [3, 10, 30, 100, 300, 500]

    while len(observations) < count:
        batch_size = rng.choice(batch_sizes)
        groups = {}

        for index in range(batch_size):
            endpoint = rng.choice(endpoints)
            method = rng.choice(methods)
            key = (endpoint, method)

            if key not in groups:
                groups[key] = {
                    "identities": [],
                    "clients": [],
                    "statuses": [],
                    "latencies": [],
                    "response_sizes": [],
                }

            group = groups[key]
            group["identities"].append(f"identity-{index % 40}")
            group["clients"].append(f"client-{index % 15}")
            group["statuses"].append(
                rng.choices([200, 201, 400], [90, 8, 2])[0]
            )
            group["latencies"].append(rng.uniform(20, 180))
            group["response_sizes"].append(rng.randint(100, 5000))

        for (endpoint, method), group in groups.items():
            statuses = group["statuses"]
            latencies = group["latencies"]
            sizes = group["response_sizes"]
            request_count = len(statuses)

            observations.append(
                BehavioralObservation(
                    endpoint_path=endpoint,
                    method=method,
                    window_seconds=60,
                    request_count=request_count,
                    unique_identity_count=len(set(group["identities"])),
                    unique_client_count=len(set(group["clients"])),
                    client_error_count=sum(
                        status >= 400 and status < 500
                        for status in statuses
                    ),
                    server_error_count=sum(
                        status >= 500 for status in statuses
                    ),
                    auth_failure_count=0,
                    mean_latency_ms=statistics.fmean(latencies),
                    latency_stddev_ms=statistics.pstdev(latencies),
                    mean_response_size_bytes=statistics.fmean(sizes),
                    response_size_stddev_bytes=statistics.pstdev(sizes),
                    data_origin="synthetic",
                )
            )

            if len(observations) >= count:
                break

    return observations[:count]
