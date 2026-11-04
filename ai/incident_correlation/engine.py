from collections import defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from ai.telemetry.models import TelemetryEvent
from ai.incident_correlation.models import (
    IncidentCorrelationResult,
    IncidentEvidence,
    SecurityIncident,
)


class IncidentCorrelationEngine:
    """Correlate suspicious telemetry patterns across actors and time."""

    def __init__(
        self,
        window_seconds: int = 300,
        max_events: int = 10000,
    ):
        if window_seconds < 60:
            raise ValueError("window_seconds must be at least 60.")
        if max_events < 1:
            raise ValueError("max_events must be positive.")

        self.window_seconds = window_seconds
        self.max_events = max_events

    @staticmethod
    def _fingerprint(actor_type: str, value: str) -> str:
        return sha256(
            f"{actor_type}:{value}".encode()
        ).hexdigest()

    @staticmethod
    def _event_indicators(event: TelemetryEvent) -> list[str]:
        indicators = []

        if event.status_code in (401, 403):
            indicators.append("authentication_failure")

        if event.status_code >= 500:
            indicators.append("server_error")

        return indicators

    @staticmethod
    def _severity(
        auth_failures: int,
        server_errors: int,
        event_count: int,
    ) -> tuple[str, int]:
        if auth_failures >= 20 or server_errors >= 20:
            return "critical", 95

        if auth_failures >= 5 or server_errors >= 10 or event_count >= 100:
            return "high", 80

        if auth_failures >= 3 or server_errors >= 5 or event_count >= 30:
            return "medium", 60

        return "low", 30

    def correlate(
        self,
        events: list[TelemetryEvent],
        lookback_minutes: int = 60,
        now: datetime | None = None,
    ) -> IncidentCorrelationResult:
        if not 1 <= lookback_minutes <= 1440:
            raise ValueError("lookback_minutes must be between 1 and 1440.")

        current_time = now or datetime.now(timezone.utc)

        if current_time.tzinfo is None:
            raise ValueError("now must be timezone-aware.")

        cutoff = current_time - timedelta(minutes=lookback_minutes)

        # Deduplicate repeated event IDs across ingestion batches.
        unique_events = {}
        for event in events[-self.max_events:]:
            if cutoff <= event.timestamp <= current_time:
                unique_events.setdefault(event.event_id, event)

        groups = defaultdict(dict)

        for event in unique_events.values():
            bucket = int(event.timestamp.timestamp()) // self.window_seconds

            actors = []
            if event.identity_hash:
                actors.append(("identity", event.identity_hash))
            if event.client_hash:
                actors.append(("client", event.client_hash))

            for actor_type, actor_value in actors:
                key = (actor_type, actor_value, bucket)
                groups[key][event.event_id] = event

        incidents = []

        for (actor_type, actor_value, bucket), event_map in groups.items():
            grouped_events = sorted(
                event_map.values(),
                key=lambda event: (event.timestamp, event.event_id),
            )

            auth_failures = sum(
                event.status_code in (401, 403)
                for event in grouped_events
            )
            server_errors = sum(
                event.status_code >= 500
                for event in grouped_events
            )
            endpoints = {
                event.endpoint_path for event in grouped_events
            }

            event_count = len(grouped_events)
            endpoint_count = len(endpoints)

            qualifies = (
                auth_failures >= 3
                or server_errors >= 5
                or event_count >= 30
                or (auth_failures >= 2 and endpoint_count >= 2)
            )

            if not qualifies:
                continue

            severity, score = self._severity(
                auth_failures,
                server_errors,
                event_count,
            )

            indicators = []

            if auth_failures:
                indicators.append("authentication_failures")

            if server_errors:
                indicators.append("server_errors")

            if endpoint_count >= 3:
                indicators.append("multi_endpoint_activity")

            if event_count >= 30:
                indicators.append("high_request_volume")

            fingerprint = self._fingerprint(actor_type, actor_value)
            incident_id = "INC-" + sha256(
                f"{actor_type}:{fingerprint}:{bucket}".encode()
            ).hexdigest()[:16].upper()

            evidence = [
                IncidentEvidence(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    method=event.method,
                    endpoint_path=event.endpoint_path,
                    status_code=event.status_code,
                    indicators=self._event_indicators(event),
                )
                for event in grouped_events
            ]

            incidents.append(
                SecurityIncident(
                    incident_id=incident_id,
                    actor_type=actor_type,
                    actor_reference=fingerprint[:16],
                    severity=severity,
                    priority_score=score,
                    window_start=grouped_events[0].timestamp,
                    window_end=grouped_events[-1].timestamp,
                    event_count=event_count,
                    distinct_endpoints=endpoint_count,
                    indicators=indicators,
                    evidence=evidence,
                    summary=(
                        f"{event_count} requests correlated for a "
                        f"pseudonymous {actor_type}; "
                        f"{auth_failures} authentication failures, "
                        f"{server_errors} server errors across "
                        f"{endpoint_count} endpoints."
                    ),
                )
            )

        incidents.sort(
            key=lambda incident: (
                -incident.priority_score,
                incident.window_start,
                incident.incident_id,
            )
        )

        return IncidentCorrelationResult(
            incidents=incidents,
            events_considered=len(unique_events),
            correlation_window_seconds=self.window_seconds,
        )
