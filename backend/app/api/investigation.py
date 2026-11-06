import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ai.behavioral_intelligence import BehavioralObservation
from backend.app.api.behavioral import load_behavioral_model
from backend.app.api.discovery import assess_openapi

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/investigation", tags=["investigation"])


class InvestigationRequest(BaseModel):
    openapi_spec: dict[str, Any]
    include_explanations: bool = False
    behavioral_observations: list[BehavioralObservation] = Field(default_factory=list)


@router.post("/run")
def run_investigation(request: InvestigationRequest) -> dict[str, Any]:
    """Run static OpenAPI analysis and, when possible, optional behavior analysis.

    Authorization probes are deliberately excluded: they perform live HTTP
    requests and remain available only through the separately protected,
    explicitly allowlisted authorization endpoints.
    """
    report: dict[str, Any] = {
        "status": "completed",
        "phases": {},
        "limitations": [
            "Static attack paths are inferred from the OpenAPI structure and do not prove runtime reachability or exploitability.",
            "Machine-learning risk predictions and documented evidence matches are not proof of a vulnerability.",
            "Behavioral anomalies indicate deviation from the model baseline, not confirmed malicious activity.",
            "BOLA/BFLA probes are not run by this endpoint. Use the separately protected authorization endpoints only against explicitly authorized, allowlisted targets.",
        ],
    }

    try:
        static_result = assess_openapi(
            request.openapi_spec,
            include_explanations=request.include_explanations,
        )
        report["phases"]["static_discovery"] = {
            "status": "completed",
            "result": static_result,
        }
    except HTTPException as exc:
        report["phases"]["static_discovery"] = {
            "status": "failed",
            "detail": exc.detail,
        }
        report["status"] = "partial_failure"
        report["phases"]["behavioral"] = {
            "status": "skipped",
            "reason": "Static discovery did not complete.",
        }
        return report
    except Exception:  # defensive boundary for a multi-phase workflow
        logger.exception("Unified investigation static discovery failed")
        report["phases"]["static_discovery"] = {
            "status": "failed",
            "detail": "Static discovery failed unexpectedly.",
        }
        report["status"] = "partial_failure"
        report["phases"]["behavioral"] = {
            "status": "skipped",
            "reason": "Static discovery did not complete.",
        }
        return report

    if not request.behavioral_observations:
        report["phases"]["behavioral"] = {
            "status": "skipped",
            "reason": "No behavioral observations were supplied.",
        }
        return report

    try:
        detector = load_behavioral_model()
        if detector is None:
            report["phases"]["behavioral"] = {
                "status": "skipped",
                "reason": "No trained behavioral model is available.",
            }
            return report

        results = detector.predict(request.behavioral_observations)
        anomalous_count = sum(
            result.classification == "anomalous" for result in results
        )
        report["phases"]["behavioral"] = {
            "status": "completed",
            "model_type": "isolation_forest",
            "training_data": "synthetic",
            "observations_assessed": len(results),
            "anomalous_observations": anomalous_count,
            "results": [result.model_dump(mode="json") for result in results],
        }
    except Exception:
        logger.exception("Unified investigation behavioral analysis failed")
        report["phases"]["behavioral"] = {
            "status": "failed",
            "detail": "Behavioral analysis could not be completed. Check model availability and observation validity.",
        }
        report["status"] = "partial_failure"

    return report
