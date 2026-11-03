from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from ai.graph_intelligence.builder import build_security_graph
from ai.graph_intelligence.explanation_mapper import GraphExplanationMapper
from ai.graph_intelligence.features import extract_graph_features
from ai.graph_intelligence.relationships import ResourceRelationshipExtractor
from ai.graph_intelligence.attack_chain import build_attack_chains
from ai.graph_intelligence.attack_chain_ranker import (
    AttackChainRanker,
    rank_attack_chains,
)
from ai.risk_prediction.evidence import CRAPI_SECURITY_EVIDENCE
from ai.risk_prediction.evidence_evaluator import evaluate_against_evidence
from ai.risk_prediction.explainability import RiskPredictionExplainer
from ai.risk_prediction.xgboost_model import XGBoostRiskPredictionModel
from ai.security_context_features import build_security_context_feature_vector
from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES
from ai.security_reasoning import (
    EvidenceConfidenceEngine,
    EvidenceCorrelationEngine,
    RemediationEngine,
    SecurityReasoningEngine,
)
from api_discovery.service import discover_api
from risk_engine.scorer import calculate_risk


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "xgboost_risk_model.json"

SHAP_TOP_FEATURES = 5
SHAP_GLOBAL_FEATURES = 10

router = APIRouter(
    prefix="/api/discovery",
    tags=["API Discovery"],
)


def _load_risk_model() -> XGBoostRiskPredictionModel | None:
    """Load the optional saved model; return None if no artifact exists."""

    if not MODEL_PATH.is_file():
        return None

    return XGBoostRiskPredictionModel.load(MODEL_PATH)


def _serialize_feature_contribution(contribution: Any) -> dict[str, Any]:
    """Convert one SHAP feature contribution into an API response."""

    shap_value = float(contribution.shap_value)

    if shap_value > 0:
        direction = "increases_class_score"
    elif shap_value < 0:
        direction = "decreases_class_score"
    else:
        direction = "no_effect"

    return {
        "feature_name": contribution.feature_name,
        "feature_value": float(contribution.feature_value),
        "shap_value": shap_value,
        "direction": direction,
    }


def _serialize_class_explanation(
    class_explanation: Any,
) -> dict[str, Any]:
    """Serialize the strongest feature contributions for one class."""

    sorted_contributions = sorted(
        class_explanation.contributions,
        key=lambda item: abs(item.shap_value),
        reverse=True,
    )

    return {
        "risk_class": class_explanation.risk_class,
        "base_value": float(class_explanation.base_value),
        "raw_model_output": float(
            class_explanation.raw_model_output
        ),
        "top_features": [
            _serialize_feature_contribution(item)
            for item in sorted_contributions[:SHAP_TOP_FEATURES]
        ],
    }


def _serialize_endpoint_explanation(
    explanation: Any,
) -> dict[str, Any]:
    """Serialize an endpoint's complete class-specific explanation."""

    class_explanations = [
        _serialize_class_explanation(item)
        for item in explanation.class_explanations
    ]

    predicted_class_explanation = next(
        (
            item
            for item in class_explanations
            if item["risk_class"] == explanation.predicted_label
        ),
        None,
    )

    return {
        "available": True,
        "predicted_class": explanation.predicted_label,
        "probabilities": explanation.probabilities,
        "top_features": (
            predicted_class_explanation["top_features"]
            if predicted_class_explanation
            else []
        ),
        "class_explanations": class_explanations,
        "interpretation": (
            "SHAP values represent feature contributions to the "
            "model's raw class scores. Positive values increase "
            "the corresponding class score; negative values decrease it."
        ),
        "limitations": (
            "Model explanations describe learned model behavior. "
            "They do not independently confirm vulnerabilities."
        ),
    }


def _serialize_graph_explanations(
    explanations: list[Any],
    object_surfaces: list[Any],
) -> dict[str, Any]:
    """
    Map assessment-level graph feature contributions to object surfaces.

    Each endpoint explanation has class-specific SHAP contributions.
    The mapped evidence remains assessment-wide and is not attributed
    to the individual endpoint.
    """

    mapper = GraphExplanationMapper()
    class_explanations = []

    for endpoint_index, endpoint_explanation in enumerate(explanations):
        for class_explanation in endpoint_explanation.class_explanations:
            graph_evidence = mapper.map_contributions(
                class_explanation.contributions,
                object_surfaces,
            )

            class_explanations.append(
                {
                    "endpoint_index": endpoint_index,
                    "risk_class": class_explanation.risk_class,
                    "graph_feature_evidence": graph_evidence,
                }
            )

    return {
        "scope": "assessment_graph",
        "description": (
            "Graph features describe object-operation relationships "
            "across the entire API assessment. Their evidence is not "
            "specific to an individual endpoint."
        ),
        "class_explanations": class_explanations,
        "limitations": (
            "Operation-surface patterns are structural security signals, "
            "not proof of authorization failures or vulnerabilities. "
            "SHAP contributions describe model behavior, not verified "
            "security findings."
        ),
    }


@router.post("/openapi")
def discover_openapi(spec: dict[str, Any]):
    """Discover endpoints from an OpenAPI/Swagger specification."""

    try:
        inventory = discover_api(spec)

        return {
            "status": "success",
            "inventory": inventory.model_dump(),
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to discover OpenAPI specification: {error}",
        ) from error


@router.post("/assess")
def assess_openapi(
    spec: dict[str, Any],
    include_explanations: bool = False,
):
    """
    Run static API assessment with optional ML, SHAP, reasoning,
    evidence confidence, and remediation recommendations.
    """

    try:
        # 1. Discover endpoints.
        inventory = discover_api(spec)

        # 1a. Infer resource relationships and bounded structural paths.
        # This layer is independent of the existing ML/SHAP feature pipeline.
        relationship_graph = ResourceRelationshipExtractor(spec).extract()
        attack_chain_result = rank_attack_chains(
            build_attack_chains(relationship_graph)
        )

        attack_chain_analysis = attack_chain_result.model_dump()
        for chain_data, chain_model in zip(
            attack_chain_analysis["chains"],
            attack_chain_result.chains,
        ):
            chain_data["priority_score"] = AttackChainRanker.score(chain_model)

        attack_chain_analysis.update(
            {
                "analysis_type": "inferred_structural_paths",
                "not_confirmed_exploits": True,
                "score_interpretation": (
                    "Priority score is a relationship-confidence and path-length "
                    "heuristic, not an exploit probability."
                ),
                "limitations": (
                    "Paths are inferred from OpenAPI structure and do not prove "
                    "runtime reachability, authorization bypass, object ownership, "
                    "or exploitability."
                ),
            }
        )

        # 2. Build the API security graph.
        graph = build_security_graph(
            inventory.object_operation_surfaces
        )

        # 3. Extract graph features and endpoint feature vectors.
        graph_features = extract_graph_features(graph)

        feature_vectors = [
            build_security_context_feature_vector(endpoint, graph)
            for endpoint in inventory.endpoints
        ]

        # 4. Load the optional model and predict in one batch.
        risk_model = _load_risk_model()

        ml_predictions = None
        ml_probabilities = None
        shap_explanations = None
        shap_global_importance = None
        graph_explanations = None

        if risk_model is not None and feature_vectors:
            ml_predictions = risk_model.predict(feature_vectors)
            ml_probabilities = risk_model.predict_proba(feature_vectors)

            # 5. Generate SHAP explanations only when requested.
            if include_explanations:
                explainer = RiskPredictionExplainer(risk_model)

                shap_explanations = explainer.explain(
                    feature_vectors
                )

                shap_global_importance = (
                    explainer.global_feature_importance(
                        feature_vectors
                    )[:SHAP_GLOBAL_FEATURES]
                )

                graph_explanations = _serialize_graph_explanations(
                    shap_explanations,
                    inventory.object_operation_surfaces,
                )

        # 6. Initialize assessment engines.
        reasoning_engine = SecurityReasoningEngine()
        correlation_engine = EvidenceCorrelationEngine()
        confidence_engine = EvidenceConfidenceEngine()
        remediation_engine = RemediationEngine()

        # 7. Assess every endpoint independently.
        endpoint_assessments = []

        for index, endpoint in enumerate(inventory.endpoints):
            baseline_assessment = calculate_risk(endpoint)

            predicted_label = (
                ml_predictions[index]
                if ml_predictions is not None
                else None
            )

            evidence_evaluation = evaluate_against_evidence(
                path=endpoint.path,
                method=endpoint.method,
                evidence=CRAPI_SECURITY_EVIDENCE,
                predicted_label=predicted_label,
            )

            matching_evidence = [
                item
                for item in CRAPI_SECURITY_EVIDENCE
                if (
                    item.path == endpoint.path
                    and item.method.upper() == endpoint.method.upper()
                )
            ]

            # 8. Generate human-readable security reasoning.
            security_reasoning = reasoning_engine.analyze_endpoint(
                endpoint,
                documented_evidence=CRAPI_SECURITY_EVIDENCE,
                object_surfaces=inventory.object_operation_surfaces,
                shap_explanation=(
                    shap_explanations[index]
                    if shap_explanations is not None
                    else None
                ),
            )

            # 9. Correlate endpoint evidence.
            normalized_evidence = correlation_engine.normalize_endpoint(
                reasoning=security_reasoning,
                predicted_label=predicted_label,
                ml_prediction_available=(
                    ml_predictions is not None
                    and ml_probabilities is not None
                ),
            )

            evidence_correlation = correlation_engine.correlate(
                normalized_evidence
            )

            # 10. Assess evidence reliability and independence.
            evidence_assessment = confidence_engine.assess(
                correlation=evidence_correlation,
                baseline_score=baseline_assessment.score,
                baseline_severity=baseline_assessment.severity,
            )

            # 11. Generate remediation recommendations.
            remediation_plan = remediation_engine.generate(
                reasoning=security_reasoning,
                risk_prioritization=(
                    evidence_assessment.risk_prioritization
                ),
            )

            security_reasoning_response = security_reasoning.model_dump()

            security_reasoning_response["evidence_correlation"] = (
                evidence_correlation.model_dump()
            )

            security_reasoning_response["evidence_assessment"] = (
                evidence_assessment.model_dump()
            )

            security_reasoning_response["remediation_plan"] = (
                remediation_plan.model_dump()
            )

            # 12. Serialize the optional ML prediction.
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
                    "predicted_label": predicted_label,
                    "class_probabilities": ml_probabilities[index],
                    "model_type": "xgboost",
                    "training_data": "synthetic",
                    "limitations": (
                        "Predictions are experimental and trained on "
                        "synthetic data; they are not verified findings."
                    ),
                }

            endpoint_assessment = {
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
                "security_reasoning": security_reasoning_response,
            }

            if include_explanations:
                if shap_explanations is not None:
                    endpoint_assessment["shap_explanation"] = (
                        _serialize_endpoint_explanation(
                            shap_explanations[index]
                        )
                    )
                else:
                    endpoint_assessment["shap_explanation"] = {
                        "available": False,
                        "reason": (
                            "A trained model artifact and endpoint "
                            "features are required for SHAP explanations."
                        ),
                    }

            endpoint_assessments.append(endpoint_assessment)

        # 13. Calculate assessment summary counters.
        evidence_matched_count = sum(
            assessment["security_evidence"]["has_security_evidence"]
            for assessment in endpoint_assessments
        )

        reasoning_finding_count = sum(
            len(assessment["security_reasoning"]["findings"])
            for assessment in endpoint_assessments
        )

        reasoning_review_count = sum(
            assessment["security_reasoning"]["overall_assessment"]
            != "no_review_signal"
            for assessment in endpoint_assessments
        )

        correlation_relationship_count = sum(
            assessment["security_reasoning"][
                "evidence_correlation"
            ]["total_relationships"]
            for assessment in endpoint_assessments
        )

        high_evidence_strength_count = sum(
            assessment["security_reasoning"][
                "evidence_assessment"
            ]["evidence_strength"]["level"] == "high"
            for assessment in endpoint_assessments
        )

        high_priority_count = sum(
            assessment["security_reasoning"][
                "evidence_assessment"
            ]["risk_prioritization"]["priority_level"]
            in ("high", "critical")
            for assessment in endpoint_assessments
        )

        average_evidence_strength = (
            round(
                sum(
                    assessment["security_reasoning"][
                        "evidence_assessment"
                    ]["evidence_strength"]["score"]
                    for assessment in endpoint_assessments
                )
                / len(endpoint_assessments),
                2,
            )
            if endpoint_assessments
            else 0.0
        )

        remediation_recommendation_count = sum(
            assessment["security_reasoning"][
                "remediation_plan"
            ]["total_recommendations"]
            for assessment in endpoint_assessments
        )

        high_priority_remediation_count = sum(
            recommendation["priority"] in ("high", "critical")
            for assessment in endpoint_assessments
            for recommendation in assessment["security_reasoning"][
                "remediation_plan"
            ]["recommendations"]
        )

        # 14. Build the assessment response.
        response = {
            "status": "success",
            "assessment_type": "openapi_static_analysis",
            "vulnerabilities_confirmed": False,
            "evidence_catalog": "CRAPI_SECURITY_EVIDENCE",
            "inventory": inventory.model_dump(),
            "security_graph": graph.model_dump(),
            "resource_relationship_graph": relationship_graph.model_dump(),
            "attack_chain_analysis": attack_chain_analysis,
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
                "resource_relationship_count": len(
                    relationship_graph.relationships
                ),
                "inferred_attack_chain_count": (
                    attack_chain_result.total_chains_found
                ),
                "attack_chain_analysis_truncated": attack_chain_result.truncated,
                "assessed_endpoints": len(endpoint_assessments),
                "security_context_feature_count": len(
                    SECURITY_CONTEXT_FEATURE_NAMES
                ),
                "endpoints_matching_documented_evidence": (
                    evidence_matched_count
                ),
                "security_reasoning_endpoints_requiring_review": (
                    reasoning_review_count
                ),
                "security_reasoning_findings": reasoning_finding_count,
                "evidence_correlation_relationships": (
                    correlation_relationship_count
                ),
                "high_evidence_strength_endpoints": (
                    high_evidence_strength_count
                ),
                "high_or_critical_priority_endpoints": (
                    high_priority_count
                ),
                "average_evidence_strength": (
                    average_evidence_strength
                ),
                "remediation_recommendations": (
                    remediation_recommendation_count
                ),
                "high_or_critical_remediation_recommendations": (
                    high_priority_remediation_count
                ),
                "ml_predictions_available": (
                    ml_predictions is not None
                    and ml_probabilities is not None
                ),
            },
            "endpoint_assessments": endpoint_assessments,
        }

        # 15. Add assessment-level SHAP information only when requested.
        if include_explanations:
            if shap_explanations is not None:
                response["shap_explainability"] = {
                    "available": True,
                    "method": "SHAP TreeExplainer",
                    "scope": "endpoints_in_this_assessment",
                    "global_feature_importance": [
                        {
                            "feature_name": item["feature_name"],
                            "mean_absolute_shap": (
                                item["mean_absolute_shap"]
                            ),
                        }
                        for item in shap_global_importance
                    ],
                    "graph_explanations": graph_explanations,
                    "limitations": (
                        "Global importance is calculated over the "
                        "endpoints in this assessment only. SHAP "
                        "contributions explain model behavior and "
                        "do not confirm vulnerabilities."
                    ),
                }
            else:
                response["shap_explainability"] = {
                    "available": False,
                    "method": "SHAP TreeExplainer",
                    "reason": (
                        "A trained model artifact and endpoint "
                        "features are required for SHAP explanations."
                    ),
                }

        return response

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to assess OpenAPI specification: {error}",
        ) from error