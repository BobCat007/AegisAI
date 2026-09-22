from api_discovery.models import APIEndpoint

from ai.graph_intelligence.features import extract_graph_features
from ai.graph_intelligence.models import APISecurityGraph
from ai.security_context import APISecurityContext
from risk_engine.features import extract_feature_vector


def build_security_context(
    endpoint: APIEndpoint,
    graph: APISecurityGraph,
) -> APISecurityContext:
    """
    Build a combined security context from endpoint-level
    and graph-level intelligence.
    """

    endpoint_features = extract_feature_vector(endpoint)
    graph_features = extract_graph_features(graph)

    return APISecurityContext(
        endpoint_features=endpoint_features,
        graph_features=graph_features,
    )
