from ai.graph_intelligence.features import extract_graph_features
from ai.graph_intelligence.models import APISecurityGraph
from ai.security_context import APISecurityContext
from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES
from risk_engine.features import extract_feature_vector
from api_discovery.models import APIEndpoint


def extract_security_context_feature_vector(
    context: APISecurityContext,
) -> list[float]:
    """
    Convert the combined API security context into
    one deterministic ML-ready feature vector.

    The vector contains endpoint-level features first,
    followed by graph-level features in the canonical
    security-context schema order.
    """
    graph_features = context.graph_features

    return [
        *context.endpoint_features,
        *[
            float(graph_features[name])
            for name in SECURITY_CONTEXT_FEATURE_NAMES[
                len(context.endpoint_features):
            ]
        ],
    ]


def build_security_context_feature_vector(
    endpoint: APIEndpoint,
    graph: APISecurityGraph,
) -> list[float]:
    """
    Build the combined ML-ready feature vector directly
    from an API endpoint and its security graph.
    """
    endpoint_features = extract_feature_vector(endpoint)
    graph_features = extract_graph_features(graph)

    context = APISecurityContext(
        endpoint_features=endpoint_features,
        graph_features=graph_features,
    )

    return extract_security_context_feature_vector(context)
