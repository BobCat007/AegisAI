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


def build_identified_graph_training_samples(
    endpoints: list[APIEndpoint],
) -> list[tuple[str, list[float], str, float]]:
    """
    Build graph training samples with explicit endpoint identifiers.

    Each sample contains:
        endpoint_id
        security-context feature vector
        risk label
        graph-aware contextual risk score

    All graph scenarios generated for the same endpoint share
    the same endpoint identifier.
    """
    scenarios = build_graph_scenarios()

    samples: list[tuple[str, list[float], str, float]] = []

    for endpoint_index, endpoint in enumerate(endpoints):
        endpoint_id = f"endpoint_{endpoint_index}"
        risk_label = get_risk_label(endpoint)

        for scenario in scenarios:
            graph = build_security_graph(scenario)

            feature_vector = build_security_context_feature_vector(
                endpoint,
                graph,
            )

            graph_context_score = get_graph_context_score(
                endpoint,
                graph,
            )

            samples.append(
                (
                    endpoint_id,
                    feature_vector,
                    risk_label,
                    graph_context_score,
                )
            )

    return samples


def build_graph_training_samples(
    endpoints: list[APIEndpoint],
) -> list[tuple[list[float], str, float]]:
    """
    Build graph training samples using the existing return format.

    Preserves backward compatibility with callers expecting:
        security-context feature vector
        deterministic endpoint risk label
        graph-aware contextual risk score

    Endpoint IDs are generated internally but omitted from
    the returned samples.
    """
    identified_samples = build_identified_graph_training_samples(
        endpoints
    )

    return [
        (feature_vector, risk_label, graph_context_score)
        for _, feature_vector, risk_label, graph_context_score
        in identified_samples
    ]
