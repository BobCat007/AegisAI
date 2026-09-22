from api_discovery.models import APIEndpoint
from ai.graph_intelligence.builder import build_security_graph
from ai.security_context_features import (
    build_security_context_feature_vector,
)
from scripts.generate_graph_scenarios import build_graph_scenarios
from scripts.generate_training_data import get_risk_label


def build_graph_training_samples(
    endpoints: list[APIEndpoint],
) -> list[tuple[list[float], str]]:
    """
    Combine generated endpoints with controlled graph scenarios.

    Each returned sample contains:

        28-feature security vector
        deterministic endpoint risk label

    Graph context changes the feature representation,
    while the initial training label remains based on the
    existing endpoint-level deterministic risk engine.
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
