from pathlib import Path

from fastapi import APIRouter, HTTPException

from ai.behavioral_intelligence import (
    BehavioralAssessmentRequest,
    IsolationForestBehavioralDetector,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

BEHAVIORAL_MODEL_PATH = (
    PROJECT_ROOT
    / "data"
    / "models"
    / "isolation_forest_behavioral.joblib"
)

router = APIRouter(
    prefix="/api/behavior",
    tags=["Behavioral Intelligence"],
)


def load_behavioral_model():
    if not BEHAVIORAL_MODEL_PATH.is_file():
        return None

    return IsolationForestBehavioralDetector.load(
        BEHAVIORAL_MODEL_PATH
    )


@router.post("/assess")
def assess_behavior(
    request: BehavioralAssessmentRequest,
):
    """Assess caller-supplied aggregated API traffic observations."""

    try:
        detector = load_behavioral_model()

        if detector is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Behavioral model is unavailable. "
                    "Train the Isolation Forest model first."
                ),
            )

        results = detector.predict(request.observations)

        anomalous_count = sum(
            result.classification == "anomalous"
            for result in results
        )

        return {
            "status": "success",
            "model_type": "isolation_forest",
            "model_available": True,
            "training_data": "synthetic",
            "observations_assessed": len(results),
            "anomalous_observations": anomalous_count,
            "results": [
                result.model_dump()
                for result in results
            ],
            "limitations": [
                "The current model was trained using synthetic baseline data.",
                "Synthetic training validates the pipeline only.",
                "Anomalous behavior does not independently establish "
                "malicious activity or a vulnerability.",
                "This endpoint analyzes aggregated observations and "
                "does not collect API traffic itself.",
                "Production use requires representative runtime baseline "
                "data and independent evaluation.",
            ],
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Behavioral assessment failed: {error}",
        ) from error
