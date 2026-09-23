from ai.graph_intelligence.features import (
    extract_graph_features,
    extract_target_graph_features,
)
from ai.graph_intelligence.models import APISecurityGraph
from ai.security_context import APISecurityContext
from ai.security_context_schema import (
    SECURITY_CONTEXT_FEATURE_NAMES,
    TARGET_SECURITY_CONTEXT_FEATURE_NAMES,
)
from risk_engine.features import extract_feature_vector
from api_discovery.models import APIEndpoint


def extract_security_context_feature_vector(
    context: APISecurityContext,
) -> list[float]:
    """
    Convert endpoint-level and aggregate graph-level
    intelligence into the 31-feature security-context vector.

    Target-aware graph features remain separate and are not
    included in this vector.
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


def extract_target_security_context_feature_vector(
    context: APISecurityContext,
) -> list[float]:
    """
    Convert endpoint-level, aggregate graph-level, and
    target-aware graph-level intelligence into the
    32-feature target-aware vector.
    """
    endpoint_feature_count = len(context.endpoint_features)

    graph_feature_names = TARGET_SECURITY_CONTEXT_FEATURE_NAMES[
        endpoint_feature_count:
    ]

    graph_features = context.graph_features
    target_graph_features = context.target_graph_features

    return [
        *context.endpoint_features,
        *[
            float(graph_features[name])
            for name in graph_feature_names
            if name in graph_features
        ],
        *[
            float(target_graph_features[name])
            for name in graph_feature_names
            if name in target_graph_features
        ],
    ]


def build_security_context_feature_vector(
    endpoint: APIEndpoint,
    graph: APISecurityGraph,
) -> list[float]:
    """
    Build the 31-feature security-context vector.

    Target-aware graph features are calculated and stored in the
    security context but are intentionally not included in this
    vector.
    """
    endpoint_features = extract_feature_vector(endpoint)
    graph_features = extract_graph_features(graph)
    target_graph_features = extract_target_graph_features(graph)

    context = APISecurityContext(
        endpoint_features=endpoint_features,
        graph_features=graph_features,
        target_graph_features=target_graph_features,
    )

    return extract_security_context_feature_vector(context)


def build_target_security_context_feature_vector(
    endpoint: APIEndpoint,
    graph: APISecurityGraph,
) -> list[float]:
    """
    Build the 32-feature target-aware security-context vector.
    """
    endpoint_features = extract_feature_vector(endpoint)
    graph_features = extract_graph_features(graph)
    target_graph_features = extract_target_graph_features(graph)

    context = APISecurityContext(
        endpoint_features=endpoint_features,
        graph_features=graph_features,
        target_graph_features=target_graph_features,
    )

    return extract_target_security_context_feature_vector(context)
