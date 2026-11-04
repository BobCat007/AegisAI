"""Convert correlated suspected incidents into analyst-facing alerts."""

from ai.alerts.models import SecurityAlert
from ai.alerts.store import AlertStore


class AlertEngine:
    def __init__(self, store=None):
        self.store = store or AlertStore()

    def create_from_incident(self, incident):
        alert = SecurityAlert(
            incident_id=incident.incident_id,
            severity=incident.severity,
            priority_score=incident.priority_score,
            summary=incident.summary,
            actor_type=incident.actor_type,
            actor_reference=incident.actor_reference,
        )
        return self.store.create_if_absent(alert)
