from typing import Any

from fastapi import APIRouter, HTTPException

from ai.graph_intelligence.builder import build_security_graph
from ai.graph_intelligence.features import extract_graph_features
from ai.security_context_features import (
    build_security_context_feature_vector,
)
from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES
from api_discovery.models import APIEndpoint
from api_discovery.service import discover_api
from risk_engine.scorer import calculate_risk


router = APIRouter(
    prefix="/api/discovery",
    tags=["API Discovery"],
)


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
    Discover an API and combine its endpoint risk assessments
    with graph-based security context.

    This endpoint performs specification analysis only. It does
    not send requests to the target API or confirm vulnerabilities.
    """

    try:
        # 1. Discover the API.
        inventory = discover_api(spec)

        # 2. Construct graph intelligence from discovered object surfaces.
        graph = build_security_graph(
            inventory.object_operation_surfaces
        )

        graph_features = extract_graph_features(graph)

        # 3. Assess each endpoint using the existing baseline scorer
        # and construct its combined security-context feature vector.
        endpoint_assessments = []

        for endpoint in inventory.endpoints:
            baseline_assessment = calculate_risk(endpoint)

            security_context_features = (
                build_security_context_feature_vector(
                    endpoint,
                    graph,
                )
            )

            endpoint_assessments.append(
                {
                    "path": endpoint.path,
                    "method": endpoint.method,
                    "operation_id": endpoint.operation_id,
                    "operation_category": endpoint.operation_category,
                    "baseline_risk": baseline_assessment.model_dump(),
                    "security_context": {
                        "feature_names": list(
                            SECURITY_CONTEXT_FEATURE_NAMES
                        ),
                        "feature_vector": security_context_features,
                    },
                }
            )

        return {
            "status": "success",
            "assessment_type": "openapi_static_analysis",
            "vulnerabilities_confirmed": False,
            "inventory": inventory.model_dump(),
            "security_graph": graph.model_dump(),
            "graph_features": graph_features,
            "summary": {
                "total_endpoints": inventory.total_endpoints,
                "total_object_surfaces": len(
                    inventory.object_operation_surfaces
                ),
                "assessed_endpoints": len(endpoint_assessments),
                "security_context_feature_count": len(
                    SECURITY_CONTEXT_FEATURE_NAMES
                ),
            },
            "endpoint_assessments": endpoint_assessments,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to assess OpenAPI specification: {exc}",
        ) from exc
