"""Bounded JSONL persistence for normalized telemetry events."""

import os
import tempfile
import threading
from pathlib import Path

from ai.telemetry.models import TelemetryEvent


class TelemetryEventStore:
    """Persist telemetry batches while retaining only the newest events."""

    _lock = threading.RLock()

    def __init__(
        self,
        path: str | Path | None = None,
        max_events: int | None = None,
    ) -> None:
        configured_path = path or os.getenv(
            "AEGISAI_TELEMETRY_PATH",
            "data/telemetry/events.jsonl",
        )
        self.path = Path(configured_path)

        if max_events is None:
            try:
                max_events = int(os.getenv("AEGISAI_TELEMETRY_MAX_EVENTS", "100000"))
            except ValueError:
                max_events = 100000

        self.max_events = max(1, max_events)

    def append_events(self, events: list[TelemetryEvent]) -> int:
        """Atomically persist a batch and enforce the configured retention cap."""
        if not events:
            return 0

        serialized = [event.model_dump_json() for event in events]

        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)

            existing = []
            if self.path.exists():
                existing = self.path.read_text(encoding="utf-8").splitlines()

            combined = existing + serialized
            retained = combined[-self.max_events:]

            fd, temporary_path = tempfile.mkstemp(
                prefix=self.path.name + ".",
                suffix=".tmp",
                dir=self.path.parent,
            )

            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write("\n".join(retained))
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())

                os.replace(temporary_path, self.path)

            finally:
                if os.path.exists(temporary_path):
                    os.unlink(temporary_path)

        return len(events)

    def read_events(self, limit: int | None = None) -> list[TelemetryEvent]:
        """Read retained events, optionally returning only the newest records."""
        if not self.path.exists():
            return []

        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()

        if limit is not None:
            lines = lines[-max(0, limit):] if limit else []

        events = []
        for line in lines:
            try:
                events.append(TelemetryEvent.model_validate_json(line))
            except Exception:
                # Ignore malformed historical records rather than crashing ingestion.
                continue

        return events
