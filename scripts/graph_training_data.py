from api_discovery.models import APIEndpoint
from ai.graph_intelligence.builder import build_security_graph
from ai.graph_intelligence.features import (
    extract_target_graph_features,
)
from ai.security_context_features import (
    build_security_context_feature_vector,
)
from ai.graph_intelligence.models import APISecurityGraph
from scripts.generate_graph_scenarios import build_graph_scenarios
from scripts.generate_training_data import get_risk_label
from risk_engine.scorer import calculate_risk


GRAPH_CONTEXT_RISK_BONUS = 10.0


def has_graph_context_risk(
    endpoint: APIEndpoint,
    graph: APISecurityGraph,
) -> bool:
    """
    Determine whether the graph provides additional contextual
    risk evidence for the target endpoint.

    A delete-without-read relationship is treated as additional
    evidence only when the endpoint itself is a DELETE operation.
    """
    target_graph_features = extract_target_graph_features(graph)

    return (
        endpoint.method == "DELETE"
        and target_graph_features["target_delete_without_read"] == 1
    )


def get_graph_context_score(
    endpoint: APIEndpoint,
    graph: APISecurityGraph,
) -> float:
    """
    Calculate the contextual security score.

    The deterministic endpoint risk score remains the baseline.
    Graph context contributes a fixed contextual bonus only when
    the target DELETE operation exists without a corresponding
    READ operation.
    """
    assessment = calculate_risk(endpoint)

    score = assessment.score

    if has_graph_context_risk(endpoint, graph):
        score = min(
            score + GRAPH_CONTEXT_RISK_BONUS,
            100.0,
        )

    return score


def get_graph_context_severity(
    endpoint: APIEndpoint,
    graph: APISecurityGraph,
) -> str:
    """
    Convert the graph-aware contextual score into a severity.
    """
    score = get_graph_context_score(
        endpoint,
        graph,
    )

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "medium"

    return "low"


def build_graph_training_samples(
    endpoints: list[APIEndpoint],
) -> list[tuple[list[float], str]]:
    """
    Combine generated endpoints with controlled graph scenarios.

    Each returned sample contains:

        28-feature security vector
        deterministic endpoint risk label

    Graph-aware score and severity are calculated separately
    and will be incorporated into the dataset contract in a
    later step.
    """
    scenarios = build_graph_scenarios()

    samples: list[tuple[list[float], str]] = []

    for endpoint in endpoints:
        risk_label = get_risk_label(endpoint)

        for scenario in scenarios:
            graph = build_security_graph(scenario)

            feature_vector = build_security_context_feature_vector(
                endpoint,
                graph,
            )

            samples.append(
                (
                    feature_vector,
                    risk_label,
                )
            )

    return samples
