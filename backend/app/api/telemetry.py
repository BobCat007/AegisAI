"""External batch telemetry ingestion API."""

import logging

from fastapi import APIRouter, HTTPException

from ai.telemetry.models import TelemetryBatch
from ai.telemetry.processor import aggregate_events
from ai.telemetry.store import TelemetryEventStore
from ai.knowledge.ingestion import get_knowledge_ingestion_service
from backend.app.api.behavioral import load_behavioral_model

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/telemetry",
    tags=["Telemetry Ingestion"],
)


def get_telemetry_store() -> TelemetryEventStore:
    return TelemetryEventStore()


@router.post("/events")
def ingest_telemetry(request: TelemetryBatch):
    """
    Accept normalized request/response metadata.

    Telemetry persistence succeeds independently of model availability.
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
        # Accepted telemetry must not be lost because an optional model failed.
        logger.exception("Behavioral assessment failed for telemetry batch")
        assessment_status = "assessment_failed"

    return {
        "status": "accepted",
        "events_received": stored_count,
        "observations_generated": len(observations),
        "behavioral_assessment": assessment_status,
        "anomalous_observations": anomalous_count,
        "results": serialized_results,
        "limitations": [
            "Events are supplied by an external collector or target-side agent.",
            "This endpoint does not passively intercept network traffic.",
            "Identity and client identifiers must be pseudonymized by the sender.",
            "Missing identity or client hashes are excluded from uniqueness metrics.",
            "Behavioral anomalies are review signals, not proof of malicious activity.",
            "A trained behavioral model and representative runtime baseline are "
            "required for meaningful production detection.",
        ],
    }
