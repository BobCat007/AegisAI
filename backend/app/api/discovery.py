from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from ai.graph_intelligence.builder import build_security_graph
from ai.graph_intelligence.features import extract_graph_features
from ai.risk_prediction.evidence import CRAPI_SECURITY_EVIDENCE
from ai.risk_prediction.evidence_evaluator import evaluate_against_evidence
from ai.risk_prediction.xgboost_model import XGBoostRiskPredictionModel
from ai.security_context_features import build_security_context_feature_vector
from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES
from api_discovery.service import discover_api
from risk_engine.scorer import calculate_risk


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "xgboost_risk_model.json"

router = APIRouter(
    prefix="/api/discovery",
    tags=["API Discovery"],
)


def _load_risk_model() -> XGBoostRiskPredictionModel | None:
    """Load the optional saved model; return None if no artifact exists."""
    if not MODEL_PATH.is_file():
        return None

    return XGBoostRiskPredictionModel.load(MODEL_PATH)


@router.post("/openapi")
def discover_openapi(spec: dict[str, Any]):
    """Discover endpoints from an OpenAPI/Swagger specification."""
    try:
        inventory = discover_api(spec)

        return {
            "status": "success",
            "inventory": inventory.model_dump(),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to process OpenAPI specification: {exc}",
        ) from exc


@router.post("/assess")
def assess_openapi(spec: dict[str, Any]):
    """
    Perform static OpenAPI analysis with baseline risk, graph
    intelligence, optional experimental ML predictions, and
    independently documented security evidence.

    This endpoint does not send requests to the target API or
    independently verify vulnerabilities.
    """
    try:
        # 1. Discover the API.
        inventory = discover_api(spec)

        # 2. Build graph intelligence.
        graph = build_security_graph(
            inventory.object_operation_surfaces
        )
        graph_features = extract_graph_features(graph)

        # 3. Build feature vectors for all discovered endpoints.
        feature_vectors = [
            build_security_context_feature_vector(endpoint, graph)
            for endpoint in inventory.endpoints
        ]

        # 4. Load the optional model and predict in one batch.
        risk_model = _load_risk_model()
        ml_predictions = None
        ml_probabilities = None

        if risk_model is not None and feature_vectors:
            ml_predictions = risk_model.predict(feature_vectors)
            ml_probabilities = risk_model.predict_proba(feature_vectors)

        # 5. Assess each endpoint independently.
        endpoint_assessments = []

        for index, endpoint in enumerate(inventory.endpoints):
            baseline_assessment = calculate_risk(endpoint)

            evidence_evaluation = evaluate_against_evidence(
                path=endpoint.path,
                method=endpoint.method,
                evidence=CRAPI_SECURITY_EVIDENCE,
            )

            matching_evidence = [
                item
                for item in CRAPI_SECURITY_EVIDENCE
                if (
                    item.path == endpoint.path
                    and item.method.upper() == endpoint.method.upper()
                )
            ]

            if ml_predictions is None or ml_probabilities is None:
                ml_assessment = {
                    "available": False,
                    "predicted_label": None,
                    "class_probabilities": None,
                    "model_type": "xgboost",
                    "training_data": "synthetic",
                    "limitations": (
                        "No saved model artifact is available. "
                        "Only baseline static risk assessment was performed."
                    ),
                }
            else:
                ml_assessment = {
                    "available": True,
                    "predicted_label": ml_predictions[index],
                    "class_probabilities": ml_probabilities[index],
                    "model_type": "xgboost",
                    "training_data": "synthetic",
                    "limitations": (
                        "Experimental prediction trained on synthetic data. "
                        "This prediction is not proof of a vulnerability "
                        "or a validated real-world risk estimate."
                    ),
                }

            endpoint_assessments.append(
                {
                    "path": endpoint.path,
                    "method": endpoint.method,
                    "operation_id": endpoint.operation_id,
                    "operation_category": endpoint.operation_category,
                    "baseline_risk": baseline_assessment.model_dump(),
                    "ml_risk_prediction": ml_assessment,
                    "security_context": {
                        "feature_names": list(
                            SECURITY_CONTEXT_FEATURE_NAMES
                        ),
                        "feature_vector": feature_vectors[index],
                    },
                    "security_evidence": {
                        **evidence_evaluation.model_dump(),
                        "evidence_details": [
                            item.model_dump()
                            for item in matching_evidence
                        ],
                    },
                }
            )

        evidence_matched_count = sum(
            assessment["security_evidence"]["has_security_evidence"]
            for assessment in endpoint_assessments
        )

        return {
            "status": "success",
            "assessment_type": "openapi_static_analysis",
            "vulnerabilities_confirmed": False,
            "evidence_catalog": "CRAPI_SECURITY_EVIDENCE",
            "inventory": inventory.model_dump(),
            "security_graph": graph.model_dump(),
            "graph_features": graph_features,
            "ml_model": {
                "available": risk_model is not None,
                "model_type": "xgboost",
                "training_data": "synthetic",
                "predictions_are_experimental": True,
            },
            "summary": {
                "total_endpoints": inventory.total_endpoints,
                "total_object_surfaces": len(
                    inventory.object_operation_surfaces
                ),
                "assessed_endpoints": len(endpoint_assessments),
                "security_context_feature_count": len(
                    SECURITY_CONTEXT_FEATURE_NAMES
                ),
                "endpoints_matching_documented_evidence": (
                    evidence_matched_count
                ),
                "ml_predictions_available": (
                    risk_model is not None
                ),
            },
            "endpoint_assessments": endpoint_assessments,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to assess OpenAPI specification: {exc}",
        ) from exc
