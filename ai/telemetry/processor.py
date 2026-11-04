"""Convert raw telemetry events into behavioral observations."""

from collections import defaultdict
from datetime import timezone
from statistics import fmean, pstdev

from ai.behavioral_intelligence.models import BehavioralObservation
from ai.telemetry.models import TelemetryEvent


def aggregate_events(
    events: list[TelemetryEvent],
    window_seconds: int = 60,
) -> list[BehavioralObservation]:
    """
    Aggregate events by endpoint, HTTP method and fixed time window.

    Missing identity/client hashes are excluded from uniqueness counts.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive.")

    groups = defaultdict(list)

    for event in events:
        timestamp = event.timestamp.astimezone(timezone.utc)
        epoch = int(timestamp.timestamp())
        bucket = epoch // window_seconds

        key = (event.endpoint_path, event.method, bucket)
        groups[key].append(event)

    observations = []

    for (path, method, _bucket), group in sorted(groups.items()):
        latencies = [event.latency_ms for event in group]
        response_sizes = [event.response_size_bytes for event in group]

        client_errors = sum(400 <= event.status_code < 500 for event in group)
        server_errors = sum(500 <= event.status_code < 600 for event in group)
        auth_failures = sum(
            event.status_code in (401, 403) for event in group
        )

        observations.append(
            BehavioralObservation(
                endpoint_path=path,
                method=method,
                window_seconds=float(window_seconds),
                request_count=len(group),
                unique_identity_count=len({
                    event.identity_hash
                    for event in group
                    if event.identity_hash
                }),
                unique_client_count=len({
                    event.client_hash
                    for event in group
                    if event.client_hash
                }),
                client_error_count=client_errors,
                server_error_count=server_errors,
                auth_failure_count=auth_failures,
                mean_latency_ms=fmean(latencies),
                latency_stddev_ms=pstdev(latencies),
                mean_response_size_bytes=fmean(response_sizes),
                response_size_stddev_bytes=pstdev(response_sizes),
                data_origin="runtime",
            )
        )

    return observations
