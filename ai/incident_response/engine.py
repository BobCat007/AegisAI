"""Policy-driven response planning. This module never executes security actions."""

from ai.incident_response.models import (
    ResponseActionType,
    ResponseDecision,
    ResponsePlan,
    ResponsePolicy,
)
from ai.incident_response.store import IncidentResponseStore

_SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class IncidentResponseEngine:
    def __init__(self, store: IncidentResponseStore | None = None):
        self.store = store

    def plan(self, incident, policy: ResponsePolicy | None = None) -> ResponsePlan:
        policy = policy or ResponsePolicy()

        plan = ResponsePlan(
            incident_id=incident.incident_id,
            policy_id=policy.policy_id,
            dry_run=policy.dry_run,
        )

        if not policy.enabled:
            plan.limitations.append("Response policy is disabled.")
            if self.store:
                self.store.append_plan(plan)
            return plan

        severity = str(incident.severity).lower()
        if severity not in _SEVERITY_RANK:
            raise ValueError(f"Unsupported incident severity: {severity}")

        if _SEVERITY_RANK[severity] < _SEVERITY_RANK[policy.minimum_severity]:
            plan.limitations.append(
                "Incident severity is below the policy threshold."
            )
            if self.store:
                self.store.append_plan(plan)
            return plan

        indicators = {str(item).lower() for item in incident.indicators}

        recommendations = [
            (
                ResponseActionType.CREATE_ALERT,
                "Create an alert so an analyst can review this incident.",
            ),
            (
                ResponseActionType.REQUEST_HUMAN_REVIEW,
                "Request analyst review before taking any disruptive action.",
            ),
        ]

        if incident.actor_reference:
            recommendations.append((
                ResponseActionType.WATCH_ACTOR,
                "Recommend monitoring this pseudonymous actor; no access is changed.",
            ))

        if severity in {"high", "critical"} and indicators.intersection({
            "authentication_failure",
            "server_error",
        }):
            recommendations.append((
                ResponseActionType.RECOMMEND_RATE_LIMIT,
                "Recommend reviewing rate limits for this actor; no limit is applied.",
            ))

        for action, rationale in recommendations:
            if action not in policy.allowed_actions:
                continue

            approval_required = action in policy.approval_required_actions

            if policy.dry_run:
                execution_status = "simulated"
            elif approval_required:
                execution_status = "approval_required"
            else:
                execution_status = "proposed"

            plan.decisions.append(ResponseDecision(
                incident_id=incident.incident_id,
                policy_id=policy.policy_id,
                action=action,
                execution_status=execution_status,
                approval_required=approval_required,
                executed=False,
                rationale=rationale,
                actor_type=incident.actor_type,
                actor_reference=incident.actor_reference,
            ))

        if self.store:
            self.store.append_plan(plan)

        return plan
