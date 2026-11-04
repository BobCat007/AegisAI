"""Append-only JSONL persistence and lifecycle management for alerts."""

import json
import os
from pathlib import Path
from threading import RLock

from ai.alerts.models import (
    AlertStatus,
    AlertTransition,
    SecurityAlert,
)


_ALLOWED_TRANSITIONS = {
    AlertStatus.OPEN: {
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.RESOLVED,
    },
    AlertStatus.ACKNOWLEDGED: {
        AlertStatus.OPEN,
        AlertStatus.RESOLVED,
    },
    AlertStatus.RESOLVED: set(),
}


class AlertStore:
    _lock = RLock()

    def __init__(self, path=None):
        self.path = Path(
            path or os.getenv(
                "AEGISAI_ALERT_PATH",
                "data/incidents/alerts.jsonl",
            )
        )

    def _append(self, record):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(record, separators=(",", ":"), default=str)

        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")
                handle.flush()
                os.fsync(handle.fileno())

    def read_records(self):
        if not self.path.exists():
            return []

        records = []
        with self._lock:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                        if isinstance(record, dict):
                            records.append(record)
                    except (json.JSONDecodeError, TypeError):
                        continue
        return records

    def get_alert(self, alert_id):
        records = self.read_records()
        created = next(
            (
                record for record in records
                if record.get("record_type") == "alert_created"
                and record.get("payload", {}).get("alert_id") == alert_id
            ),
            None,
        )

        if created is None:
            return None

        alert = SecurityAlert.model_validate(created["payload"])

        for record in records:
            if (
                record.get("record_type") == "alert_transition"
                and record.get("alert_id") == alert_id
            ):
                try:
                    transition = AlertTransition.model_validate(
                        record["payload"]
                    )
                    alert.status = transition.new_status
                    alert.updated_at = transition.timestamp
                except (ValueError, TypeError, KeyError):
                    continue

        return alert

    def get_by_incident(self, incident_id):
        records = self.read_records()
        for record in records:
            if (
                record.get("record_type") == "alert_created"
                and record.get("incident_id") == incident_id
            ):
                alert_id = record.get("payload", {}).get("alert_id")
                if alert_id:
                    return self.get_alert(alert_id)
        return None

    def create_if_absent(self, alert: SecurityAlert):
        with self._lock:
            existing = self.get_by_incident(alert.incident_id)
            if existing is not None:
                return existing, False

            self._append({
                "record_type": "alert_created",
                "incident_id": alert.incident_id,
                "recorded_at": alert.created_at.isoformat(),
                "payload": alert.model_dump(mode="json"),
            })
            return alert, True

    def list_alerts(self, status=None, limit=100):
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")

        records = self.read_records()
        alert_ids = [
            record.get("payload", {}).get("alert_id")
            for record in records
            if record.get("record_type") == "alert_created"
        ]

        alerts = []
        seen = set()

        for alert_id in reversed(alert_ids):
            if not alert_id or alert_id in seen:
                continue
            seen.add(alert_id)

            alert = self.get_alert(alert_id)
            if alert is None:
                continue
            if status is not None and alert.status != status:
                continue
            alerts.append(alert)

            if len(alerts) >= limit:
                break

        return alerts

    def update_status(self, alert_id, new_status, changed_by, reason):
        changed_by = changed_by.strip()
        reason = reason.strip()

        if not changed_by:
            raise ValueError("changed_by must not be empty")
        if not reason:
            raise ValueError("A transition reason is required")

        with self._lock:
            alert = self.get_alert(alert_id)
            if alert is None:
                raise KeyError("Alert not found")

            if new_status not in _ALLOWED_TRANSITIONS[alert.status]:
                raise ValueError(
                    f"Invalid alert transition: "
                    f"{alert.status.value} -> {new_status.value}"
                )

            transition = AlertTransition(
                alert_id=alert_id,
                previous_status=alert.status,
                new_status=new_status,
                changed_by=changed_by,
                reason=reason,
            )

            self._append({
                "record_type": "alert_transition",
                "alert_id": alert_id,
                "recorded_at": transition.timestamp.isoformat(),
                "payload": transition.model_dump(mode="json"),
            })

            return transition

    def get_audit(self, alert_id):
        return [
            record for record in self.read_records()
            if (
                record.get("alert_id") == alert_id
                or (
                    record.get("record_type") == "alert_created"
                    and record.get("payload", {}).get("alert_id") == alert_id
                )
            )
        ]
