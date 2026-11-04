"""External batch telemetry ingestion and incident correlation API."""

import logging

from fastapi import APIRouter, HTTPException, Query

from ai.telemetry.models import TelemetryBatch
from ai.telemetry.processor import aggregate_events
from ai.telemetry.store import TelemetryEventStore
from ai.incident_correlation import (
    IncidentCorrelationEngine,
    IncidentCorrelationResult,
)
from ai.knowledge.ingestion import get_knowledge_ingestion_service
from backend.app.api.behavioral import load_behavioral_model

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/telemetry",
    tags=["Telemetry Ingestion"],
)

MAX_CORRELATION_EVENTS = 10000


def get_telemetry_store() -> TelemetryEventStore:
    return TelemetryEventStore()


def correlate_recent_incidents(
    lookback_minutes: int = 60,
    window_seconds: int = 300,
) -> IncidentCorrelationResult:
    """Correlate retained telemetry across ingestion batches."""
    events = get_telemetry_store().read_events(
        limit=MAX_CORRELATION_EVENTS
    )

    engine = IncidentCorrelationEngine(
        window_seconds=window_seconds,
        max_events=MAX_CORRELATION_EVENTS,
    )

    return engine.correlate(
        events,
        lookback_minutes=lookback_minutes,
    )


@router.post("/events")
def ingest_telemetry(request: TelemetryBatch):
    """
    Accept normalized request/response metadata.

    Persistence, behavioral assessment and incident correlation
    operate independently so optional detection failures do not
    discard accepted telemetry.
    """
    events = request.events

    try:
        stored_count = get_telemetry_store().append_events(events)
    except OSError:
        logger.exception("Telemetry persistence failed")
        raise HTTPException(
            status_code=503,
            detail="Telemetry storage is temporarily unavailable.",
        )

    observations = aggregate_events(events)

    assessment_status = "model_unavailable"
    serialized_results = []
    anomalous_count = 0

    try:
        detector = load_behavioral_model()

        if detector is not None:
            results = detector.predict(observations)
            serialized_results = [
                result.model_dump() for result in results
            ]
            anomalous_count = sum(
                result.classification == "anomalous"
                for result in results
            )
            assessment_status = "completed"

            try:
                get_knowledge_ingestion_service().ingest_behavioral(
                    serialized_results,
                    "telemetry_ingestion",
                )
            except Exception:
                logger.exception(
                    "Knowledge ingestion failed after telemetry assessment"
                )

    except Exception:
        logger.exception("Behavioral assessment failed for telemetry batch")
        assessment_status = "assessment_failed"

    incident_status = "completed"
    incident_result = IncidentCorrelationResult(
        incidents=[],
        events_considered=0,
        correlation_window_seconds=300,
    )

    try:
        incident_result = correlate_recent_incidents()
    except Exception:
        logger.exception("Incident correlation failed after telemetry ingestion")
        incident_status = "failed"

    alert_status = "completed"
    alerts_created = 0
    try:
        alert_engine = AlertEngine(get_alert_store())
        for incident in incident_result.incidents:
            _, created = alert_engine.create_from_incident(incident)
            alerts_created += int(created)
    except Exception:
        logger.exception("Alert creation failed after incident correlation")
        alert_status = "failed"

    return {
        "status": "accepted",
        "events_received": stored_count,
        "alert_creation": alert_status,
        "alerts_created": alerts_created,
        "observations_generated": len(observations),
        "behavioral_assessment": assessment_status,
        "anomalous_observations": anomalous_count,
        "results": serialized_results,
        "incident_correlation": incident_status,
        "incident_count": len(incident_result.incidents),
        "incidents": [
            incident.model_dump(mode="json")
            for incident in incident_result.incidents
        ],
        "limitations": [
            "Events are supplied by an external collector or target-side agent.",
            "This endpoint does not passively intercept network traffic.",
            "Identity and client identifiers must be pseudonymized by the sender.",
            "Missing identity or client hashes cannot be actor-correlated.",
            "Behavioral anomalies are review signals, not proof of malicious activity.",
            "Incident correlations use heuristic rules and fixed time windows.",
            "An event may contribute to both identity and client incidents.",
            "Suspected incidents are not confirmed vulnerabilities or attacks.",
            "Only retained telemetry events within the lookback period are considered.",
            "A trained behavioral model and representative runtime baseline are "
            "required for meaningful production detection.",
        ],
    }


@router.get("/incidents")
def get_telemetry_incidents(
    lookback_minutes: int = Query(default=60, ge=1, le=1440),
    window_seconds: int = Query(default=300, ge=60, le=3600),
):
    """Retrieve suspected incidents correlated from retained telemetry."""
    try:
        result = correlate_recent_incidents(
            lookback_minutes=lookback_minutes,
            window_seconds=window_seconds,
        )
        return result.model_dump(mode="json")
    except Exception:
        logger.exception("Incident retrieval/correlation failed")
        raise HTTPException(
            status_code=503,
            detail="Incident correlation is temporarily unavailable.",
        )


# Incident response API integration
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai.incident_response import (
    IncidentResponseEngine,
    IncidentResponseStore,
    IncidentStatus,
    LifecycleTransition,
    ResponsePlan,
    ResponsePolicy,
)


class IncidentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_status: IncidentStatus
    changed_by: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)

    @field_validator("changed_by", "reason")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field must not be blank.")
        return value


def get_response_store() -> IncidentResponseStore:
    return IncidentResponseStore()


def find_correlated_incident(incident_id: str):
    """Return a currently correlated incident or raise a suitable API error."""
    try:
        result = correlate_recent_incidents()
    except Exception:
        logger.exception("Unable to verify incident before response operation")
        raise HTTPException(
            status_code=503,
            detail="Incident correlation is temporarily unavailable.",
        )

    incident = next(
        (
            item for item in result.incidents
            if item.incident_id == incident_id
        ),
        None,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident was not found in the current correlation window.",
        )

    return incident


def response_incident_exists(incident_id: str, store: IncidentResponseStore) -> bool:
    """Allow existing audited incidents or currently correlated incidents."""
    if any(
        record.get("incident_id") == incident_id
        for record in store.read_records()
    ):
        return True

    try:
        result = correlate_recent_incidents()
    except Exception:
        logger.exception("Unable to verify incident reference")
        raise HTTPException(
            status_code=503,
            detail="Incident correlation is temporarily unavailable.",
        )

    return any(
        item.incident_id == incident_id
        for item in result.incidents
    )


@router.post("/incidents/{incident_id}/response-plan")
def create_incident_response_plan(
    incident_id: str,
    policy: ResponsePolicy | None = None,
):
    incident = find_correlated_incident(incident_id)
    store = get_response_store()

    try:
        plan = IncidentResponseEngine(store=store).plan(
            incident,
            policy=policy,
        )
        return plan.model_dump(mode="json")
    except Exception:
        logger.exception("Incident response planning failed")
        raise HTTPException(
            status_code=503,
            detail="Incident response planning is temporarily unavailable.",
        )


@router.patch(
    "/incidents/{incident_id}/status",
    response_model=LifecycleTransition,
)
def update_incident_status(
    incident_id: str,
    request: IncidentStatusUpdate,
):
    store = get_response_store()

    if not response_incident_exists(incident_id, store):
        raise HTTPException(
            status_code=404,
            detail="Incident was not found.",
        )

    try:
        transition = store.transition(
            incident_id=incident_id,
            new_status=request.new_status,
            changed_by=request.changed_by,
            reason=request.reason,
        )
        return transition
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except OSError:
        logger.exception("Incident lifecycle audit persistence failed")
        raise HTTPException(
            status_code=503,
            detail="Incident audit storage is temporarily unavailable.",
        )


@router.get("/incidents/{incident_id}/response-audit")
def get_incident_response_audit(incident_id: str):
    store = get_response_store()

    try:
        records = [
            record for record in store.read_records()
            if record.get("incident_id") == incident_id
        ]
    except OSError:
        logger.exception("Incident audit retrieval failed")
        raise HTTPException(
            status_code=503,
            detail="Incident audit storage is temporarily unavailable.",
        )

    if not records:
        raise HTTPException(
            status_code=404,
            detail="No response audit records were found for this incident.",
        )

    return {
        "incident_id": incident_id,
        "record_count": len(records),
        "records": records,
    }


# Alert management API
from ai.alerts import (
    AlertEngine,
    AlertStatus,
    AlertStatusUpdate as AlertStatusUpdateRequest,
    AlertStore,
    AlertTransition,
)


def get_alert_store() -> AlertStore:
    return AlertStore()


@router.get("/alerts")
def list_security_alerts(
    status: AlertStatus | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
):
    try:
        alerts = get_alert_store().list_alerts(status=status, limit=limit)
        return {
            "count": len(alerts),
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
        }
    except Exception:
        logger.exception("Alert listing failed")
        raise HTTPException(
            status_code=503,
            detail="Alert listing is temporarily unavailable.",
        )


@router.get("/alerts/{alert_id}")
def get_security_alert(alert_id: str):
    try:
        alert = get_alert_store().get_alert(alert_id)
    except Exception:
        logger.exception("Alert retrieval failed")
        raise HTTPException(
            status_code=503,
            detail="Alert retrieval is temporarily unavailable.",
        )

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return alert.model_dump(mode="json")


@router.patch(
    "/alerts/{alert_id}/status",
    response_model=AlertTransition,
)
def update_security_alert_status(
    alert_id: str,
    request: AlertStatusUpdateRequest,
):
    try:
        transition = get_alert_store().update_status(
            alert_id=alert_id,
            new_status=request.new_status,
            changed_by=request.changed_by,
            reason=request.reason,
        )
        return transition
    except KeyError:
        raise HTTPException(status_code=404, detail="Alert not found.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except OSError:
        logger.exception("Alert audit persistence failed")
        raise HTTPException(
            status_code=503,
            detail="Alert audit storage is temporarily unavailable.",
        )


@router.get("/alerts/{alert_id}/audit")
def get_security_alert_audit(alert_id: str):
    store = get_alert_store()

    try:
        alert = store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found.")

        records = store.get_audit(alert_id)
        return {
            "alert_id": alert_id,
            "record_count": len(records),
            "records": records,
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Alert audit retrieval failed")
        raise HTTPException(
            status_code=503,
            detail="Alert audit retrieval is temporarily unavailable.",
        )
