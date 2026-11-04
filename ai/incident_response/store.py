"""Append-only persistence for response decisions and incident lifecycle."""

import json
import os
from pathlib import Path
from threading import RLock
from typing import Any

from ai.incident_response.models import (
    IncidentStatus,
    LifecycleTransition,
    ResponsePlan,
)

_ALLOWED_TRANSITIONS = {
    IncidentStatus.SUSPECTED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.CONTAINED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
    },
    IncidentStatus.RESOLVED: set(),
    IncidentStatus.FALSE_POSITIVE: set(),
}


class IncidentResponseStore:
    """JSONL audit store. Records are append-only and never silently overwritten."""

    _lock = RLock()

    def __init__(self, path: str | Path | None = None):
        configured = path or os.getenv(
            "AEGISAI_RESPONSE_AUDIT_PATH",
            "data/incidents/response_audit.jsonl",
        )
        self.path = Path(configured)

    def _append(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(record, default=str, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())

    def read_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []

        records = []
        with self._lock:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        value = json.loads(line)
                        if isinstance(value, dict):
                            records.append(value)
                    except (json.JSONDecodeError, TypeError):
                        continue
        return records

    def append_plan(self, plan: ResponsePlan) -> None:
        self._append({
            "record_type": "response_plan",
            "incident_id": plan.incident_id,
            "recorded_at": plan.generated_at.isoformat(),
            "payload": plan.model_dump(mode="json"),
        })

    def get_status(self, incident_id: str) -> IncidentStatus:
        status = IncidentStatus.SUSPECTED
        for record in self.read_records():
            if (
                record.get("record_type") == "lifecycle_transition"
                and record.get("incident_id") == incident_id
            ):
                try:
                    status = IncidentStatus(record["payload"]["new_status"])
                except (KeyError, ValueError, TypeError):
                    continue
        return status

    def transition(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        changed_by: str,
        reason: str,
    ) -> LifecycleTransition:
        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")
        if not changed_by.strip():
            raise ValueError("changed_by must not be empty")
        if not reason.strip():
            raise ValueError("A transition reason is required")

        with self._lock:
            previous = self.get_status(incident_id)
            if new_status not in _ALLOWED_TRANSITIONS[previous]:
                raise ValueError(
                    f"Invalid incident transition: "
                    f"{previous.value} -> {new_status.value}"
                )

            transition = LifecycleTransition(
                incident_id=incident_id,
                previous_status=previous,
                new_status=new_status,
                changed_by=changed_by.strip(),
                reason=reason.strip(),
            )
            self._append({
                "record_type": "lifecycle_transition",
                "incident_id": incident_id,
                "recorded_at": transition.timestamp.isoformat(),
                "payload": transition.model_dump(mode="json"),
            })
            return transition
