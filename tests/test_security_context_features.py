from api_discovery.models import APIEndpoint, SecurityClassification
from ai.graph_intelligence.builder import build_security_graph
from ai.security_context_features import (
    build_security_context_feature_vector,
    build_target_security_context_feature_vector,
)
from ai.security_context_schema import (
    SECURITY_CONTEXT_FEATURE_COUNT,
    TARGET_SECURITY_CONTEXT_FEATURE_COUNT,
)
from api_discovery.models import APIObjectOperationSurface


def build_endpoint() -> APIEndpoint:
    return APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        parameters=[
            {
                "name": "user_id",
                "in": "path",
                "required": True,
            }
        ],
        security=[{"bearerAuth": []}],
        security_classification=SecurityClassification(
            is_authenticated=True,
            is_destructive=True,
            has_path_parameters=True,
            object_identifier_names=["user_id"],
            object_access_pattern="object",
        ),
    )


def build_graph(target_method: str) -> object:
    surface = APIObjectOperationSurface(
        path_template="/users/{user_id}",
        object_identifier_names=["user_id"],
        operations=["DELETE"],
        target_method=target_method,
        has_delete_operation=True,
    )

    return build_security_graph([surface])


def test_existing_security_context_vector_remains_28_features():
    endpoint = build_endpoint()
    graph = build_graph("DELETE")

    vector = build_security_context_feature_vector(
        endpoint,
        graph,
    )

    assert len(vector) == SECURITY_CONTEXT_FEATURE_COUNT
    assert len(vector) == 28


def test_target_security_context_vector_has_29_features():
    endpoint = build_endpoint()
    graph = build_graph("DELETE")

    vector = build_target_security_context_feature_vector(
        endpoint,
        graph,
    )

    assert len(vector) == TARGET_SECURITY_CONTEXT_FEATURE_COUNT
    assert len(vector) == 29


def test_target_delete_without_read_is_last_feature():
    endpoint = build_endpoint()
    graph = build_graph("DELETE")

    vector = build_target_security_context_feature_vector(
        endpoint,
        graph,
    )

    assert vector[-1] == 1.0


def test_target_delete_without_read_is_zero_for_non_delete_target():
    endpoint = build_endpoint()
    graph = build_graph("POST")

    vector = build_target_security_context_feature_vector(
        endpoint,
        graph,
    )

    assert vector[-1] == 0.0
