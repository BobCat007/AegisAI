from risk_engine.features import extract_feature_vector

from ai.security_context_features import (
    build_security_context_feature_vector,
    extract_security_context_feature_vector,
)
from ai.security_context_schema import (
    SECURITY_CONTEXT_FEATURE_COUNT,
    SECURITY_CONTEXT_FEATURE_NAMES,
)

from api_discovery.models import (
    APIEndpoint,
    APIObjectOperationSurface,
)

from ai.graph_intelligence.builder import build_security_graph
from ai.graph_intelligence.features import (
    count_objects_with_full_operation_surface,
)
from ai.graph_intelligence.models import (
    APIObjectNode,
    APIOperationEdge,
)

from ai.graph_intelligence.features import (
    count_objects_with_full_operation_surface,
    count_objects_with_mutation_without_read,
    count_objects_with_delete_without_read,
    count_objects_with_write_without_read,
    count_objects_with_multiple_mutation_types,
    count_objects_with_write_and_delete_without_read,
    extract_graph_features,
    has_target_delete_without_read,
)

from ai.graph_intelligence.schema import (
    GRAPH_FEATURE_COUNT,
    GRAPH_FEATURE_NAMES,
)

from ai.security_context import APISecurityContext

from ai.security_context_service import build_security_context

def test_build_security_graph():
    surface = APIObjectOperationSurface(
        path_template="/users/{user_id}",
        object_identifier_names=["user_id"],
        operations=["GET", "PUT", "DELETE"],
        has_read_operation=True,
        has_write_operation=True,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    assert len(graph.objects) == 1
    assert len(graph.operations) == 3

    assert isinstance(graph.objects[0], APIObjectNode)
    assert graph.objects[0].path_template == "/users/{user_id}"
    assert graph.objects[0].object_identifier_names == ["user_id"]

    methods = {
        operation.method
        for operation in graph.operations
    }

    assert methods == {"GET", "PUT", "DELETE"}

    assert all(
        isinstance(operation, APIOperationEdge)
        for operation in graph.operations
    )

    assert all(
        operation.path_template == "/users/{user_id}"
        for operation in graph.operations
    )


def test_build_multiple_object_surfaces():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "PUT"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/orders/{order_id}",
            object_identifier_names=["order_id"],
            operations=["GET", "DELETE"],
            has_read_operation=True,
            has_write_operation=False,
            has_delete_operation=True,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert len(graph.objects) == 2
    assert len(graph.operations) == 4

    assert {
        obj.path_template
        for obj in graph.objects
    } == {
        "/users/{user_id}",
        "/orders/{order_id}",
    }

    assert {
        (operation.path_template, operation.method)
        for operation in graph.operations
    } == {
        ("/users/{user_id}", "GET"),
        ("/users/{user_id}", "PUT"),
        ("/orders/{order_id}", "GET"),
        ("/orders/{order_id}", "DELETE"),
    }


def test_build_empty_security_graph():
    graph = build_security_graph([])

    assert graph.objects == []
    assert graph.operations == []


def test_count_objects_with_full_operation_surface():
    surface = APIObjectOperationSurface(
        path_template="/users/{user_id}",
        object_identifier_names=["user_id"],
        operations=["GET", "PUT", "DELETE"],
        has_read_operation=True,
        has_write_operation=True,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    assert count_objects_with_full_operation_surface(graph) == 1


def test_count_objects_with_full_operation_surface_excludes_partial_surfaces():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "PUT", "DELETE"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=True,
        ),
        APIObjectOperationSurface(
            path_template="/posts/{post_id}",
            object_identifier_names=["post_id"],
            operations=["GET"],
            has_read_operation=True,
            has_write_operation=False,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/comments/{comment_id}",
            object_identifier_names=["comment_id"],
            operations=["GET", "POST"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=False,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_full_operation_surface(graph) == 1


def test_count_objects_with_full_operation_surface_empty_graph():
    graph = build_security_graph([])

    assert count_objects_with_full_operation_surface(graph) == 0

def test_count_objects_with_mutation_without_read():
    surface = APIObjectOperationSurface(
        path_template="/admin/videos/{video_id}",
        object_identifier_names=["video_id"],
        operations=["DELETE"],
        has_read_operation=False,
        has_write_operation=False,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    assert count_objects_with_mutation_without_read(graph) == 1


def test_count_objects_with_mutation_without_read_excludes_read_surfaces():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "DELETE"],
            has_read_operation=True,
            has_write_operation=False,
            has_delete_operation=True,
        ),
        APIObjectOperationSurface(
            path_template="/orders/{order_id}",
            object_identifier_names=["order_id"],
            operations=["GET", "PUT"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=False,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_mutation_without_read(graph) == 0


def test_count_objects_with_mutation_without_read_multiple_mutations():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/admin/videos/{video_id}",
            object_identifier_names=["video_id"],
            operations=["DELETE"],
            has_read_operation=False,
            has_write_operation=False,
            has_delete_operation=True,
        ),
        APIObjectOperationSurface(
            path_template="/admin/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["PUT"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/admin/posts/{post_id}",
            object_identifier_names=["post_id"],
            operations=["POST"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_mutation_without_read(graph) == 3


def test_count_objects_with_mutation_without_read_empty_graph():
    graph = build_security_graph([])

    assert count_objects_with_mutation_without_read(graph) == 0

def test_count_objects_with_delete_without_read():
    surface = APIObjectOperationSurface(
        path_template="/admin/videos/{video_id}",
        object_identifier_names=["video_id"],
        operations=["DELETE"],
        has_read_operation=False,
        has_write_operation=False,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    assert count_objects_with_delete_without_read(graph) == 1


def test_count_objects_with_delete_without_read_excludes_read_surfaces():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "DELETE"],
            has_read_operation=True,
            has_write_operation=False,
            has_delete_operation=True,
        ),
        APIObjectOperationSurface(
            path_template="/orders/{order_id}",
            object_identifier_names=["order_id"],
            operations=["GET", "PUT"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=False,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_delete_without_read(graph) == 0


def test_count_objects_with_delete_without_read_empty_graph():
    graph = build_security_graph([])

    assert count_objects_with_delete_without_read(graph) == 0

def test_count_objects_with_write_without_read():
    surface = APIObjectOperationSurface(
        path_template="/comments/{comment_id}",
        object_identifier_names=["comment_id"],
        operations=["POST"],
        has_read_operation=False,
        has_write_operation=True,
        has_delete_operation=False,
    )

    graph = build_security_graph([surface])

    assert count_objects_with_write_without_read(graph) == 1


def test_count_objects_with_write_without_read_excludes_read_surfaces():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "PUT"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/orders/{order_id}",
            object_identifier_names=["order_id"],
            operations=["GET", "POST"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=False,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_write_without_read(graph) == 0


def test_count_objects_with_write_without_read_multiple_write_methods():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["POST"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/profiles/{profile_id}",
            object_identifier_names=["profile_id"],
            operations=["PUT"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/settings/{setting_id}",
            object_identifier_names=["setting_id"],
            operations=["PATCH"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_write_without_read(graph) == 3


def test_count_objects_with_write_without_read_excludes_delete_only_surfaces():
    surface = APIObjectOperationSurface(
        path_template="/admin/videos/{video_id}",
        object_identifier_names=["video_id"],
        operations=["DELETE"],
        has_read_operation=False,
        has_write_operation=False,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    assert count_objects_with_write_without_read(graph) == 0


def test_count_objects_with_write_without_read_empty_graph():
    graph = build_security_graph([])

    assert count_objects_with_write_without_read(graph) == 0

def test_count_objects_with_multiple_mutation_types():
    surface = APIObjectOperationSurface(
        path_template="/users/{user_id}",
        object_identifier_names=["user_id"],
        operations=["GET", "PUT", "DELETE"],
        has_read_operation=True,
        has_write_operation=True,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    assert count_objects_with_multiple_mutation_types(graph) == 1


def test_count_objects_with_multiple_mutation_types_excludes_single_mutation():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "PUT"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/comments/{comment_id}",
            object_identifier_names=["comment_id"],
            operations=["GET", "DELETE"],
            has_read_operation=True,
            has_write_operation=False,
            has_delete_operation=True,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_multiple_mutation_types(graph) == 0


def test_count_objects_with_multiple_mutation_types_detects_multiple_writes():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["POST", "PUT"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/profiles/{profile_id}",
            object_identifier_names=["profile_id"],
            operations=["PATCH", "DELETE"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=True,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_multiple_mutation_types(graph) == 2


def test_count_objects_with_multiple_mutation_types_empty_graph():
    graph = build_security_graph([])

    assert count_objects_with_multiple_mutation_types(graph) == 0

def test_count_objects_with_write_and_delete_without_read():
    surface = APIObjectOperationSurface(
        path_template="/users/{user_id}",
        object_identifier_names=["user_id"],
        operations=["PUT", "DELETE"],
        has_read_operation=False,
        has_write_operation=True,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    assert count_objects_with_write_and_delete_without_read(graph) == 1


def test_count_objects_with_write_and_delete_without_read_excludes_read_surfaces():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "PUT", "DELETE"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=True,
        ),
        APIObjectOperationSurface(
            path_template="/profiles/{profile_id}",
            object_identifier_names=["profile_id"],
            operations=["GET", "DELETE"],
            has_read_operation=True,
            has_write_operation=False,
            has_delete_operation=True,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_write_and_delete_without_read(graph) == 0


def test_count_objects_with_write_and_delete_without_read_requires_both_mutations():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["PUT"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
        APIObjectOperationSurface(
            path_template="/profiles/{profile_id}",
            object_identifier_names=["profile_id"],
            operations=["DELETE"],
            has_read_operation=False,
            has_write_operation=False,
            has_delete_operation=True,
        ),
    ]

    graph = build_security_graph(surfaces)

    assert count_objects_with_write_and_delete_without_read(graph) == 0


def test_count_objects_with_write_and_delete_without_read_empty_graph():
    graph = build_security_graph([])

    assert count_objects_with_write_and_delete_without_read(graph) == 0

def test_graph_feature_schema_count():
    assert GRAPH_FEATURE_COUNT == 6


def test_graph_feature_names_are_unique():
    assert len(GRAPH_FEATURE_NAMES) == len(set(GRAPH_FEATURE_NAMES))


def test_graph_feature_schema_order():
    assert GRAPH_FEATURE_NAMES == (
        "objects_with_full_operation_surface",
        "objects_with_mutation_without_read",
        "objects_with_delete_without_read",
        "objects_with_write_without_read",
        "objects_with_multiple_mutation_types",
        "objects_with_write_and_delete_without_read",
    )

def test_extract_graph_features():
    surfaces = [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "PUT", "DELETE"],
            has_read_operation=True,
            has_write_operation=True,
            has_delete_operation=True,
        ),
        APIObjectOperationSurface(
            path_template="/admin/{user_id}",
            object_identifier_names=["user_id"],
            operations=["DELETE"],
            has_read_operation=False,
            has_write_operation=False,
            has_delete_operation=True,
        ),
        APIObjectOperationSurface(
            path_template="/comments/{comment_id}",
            object_identifier_names=["comment_id"],
            operations=["POST"],
            has_read_operation=False,
            has_write_operation=True,
            has_delete_operation=False,
        ),
    ]

    graph = build_security_graph(surfaces)

    features = extract_graph_features(graph)

    assert features == {
        "objects_with_full_operation_surface": 1,
        "objects_with_mutation_without_read": 2,
        "objects_with_delete_without_read": 1,
        "objects_with_write_without_read": 1,
        "objects_with_multiple_mutation_types": 1,
        "objects_with_write_and_delete_without_read": 0,
    }


def test_extract_graph_features_empty_graph():
    graph = build_security_graph([])

    features = extract_graph_features(graph)

    assert features == {
        "objects_with_full_operation_surface": 0,
        "objects_with_mutation_without_read": 0,
        "objects_with_delete_without_read": 0,
        "objects_with_write_without_read": 0,
        "objects_with_multiple_mutation_types": 0,
        "objects_with_write_and_delete_without_read": 0,
    }

def test_api_security_context():
    context = APISecurityContext(
        endpoint_features=[1.0, 0.0, 1.0],
        graph_features={
            "objects_with_full_operation_surface": 2,
            "objects_with_mutation_without_read": 1,
        },
    )

    assert context.endpoint_features == [1.0, 0.0, 1.0]
    assert context.graph_features == {
        "objects_with_full_operation_surface": 2,
        "objects_with_mutation_without_read": 1,
    }


def test_api_security_context_defaults():
    context = APISecurityContext()

    assert context.endpoint_features == []
    assert context.graph_features == {}

def test_build_security_context():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="PUT",
        operation_category="update",
        parameters=[],
        responses={},
    )

    surface = APIObjectOperationSurface(
        path_template="/users/{user_id}",
        object_identifier_names=["user_id"],
        operations=["GET", "PUT", "DELETE"],
        has_read_operation=True,
        has_write_operation=True,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    context = build_security_context(endpoint, graph)

    assert len(context.endpoint_features) == 22

    assert context.graph_features == {
        "objects_with_full_operation_surface": 1,
        "objects_with_mutation_without_read": 0,
        "objects_with_delete_without_read": 0,
        "objects_with_write_without_read": 0,
        "objects_with_multiple_mutation_types": 1,
        "objects_with_write_and_delete_without_read": 0,
    }

def test_has_target_delete_without_read():
    scenarios = [
        (
            ["DELETE"],
            "DELETE",
            True,
        ),
        (
            ["PUT", "DELETE"],
            "DELETE",
            True,
        ),
        (
            ["GET", "PUT", "DELETE"],
            "DELETE",
            False,
        ),
        (
            ["POST"],
            "POST",
            False,
        ),
    ]

    for operations, target_method, expected in scenarios:
        surface = APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=operations,
            target_method=target_method,
            has_read_operation="GET" in operations,
            has_write_operation=bool(
                set(operations).intersection(
                    {"POST", "PUT", "PATCH"}
                )
            ),
            has_delete_operation="DELETE" in operations,
        )

        graph = build_security_graph([surface])

        assert has_target_delete_without_read(graph) is expected

def test_security_context_feature_schema():
    assert SECURITY_CONTEXT_FEATURE_COUNT == 28
    assert len(SECURITY_CONTEXT_FEATURE_NAMES) == 28
    assert len(set(SECURITY_CONTEXT_FEATURE_NAMES)) == 28


def test_security_context_feature_vector():
    context = APISecurityContext(
        endpoint_features=[float(index) for index in range(22)],
        graph_features={
            "objects_with_full_operation_surface": 22,
            "objects_with_mutation_without_read": 23,
            "objects_with_delete_without_read": 24,
            "objects_with_write_without_read": 25,
            "objects_with_multiple_mutation_types": 26,
            "objects_with_write_and_delete_without_read": 27,
        },
    )

    vector = extract_security_context_feature_vector(context)

    assert len(vector) == 28
    assert vector == [float(index) for index in range(28)]


def test_build_security_context_feature_vector():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="PUT",
        operation_category="update",
        parameters=[],
        responses={},
    )

    surface = APIObjectOperationSurface(
        path_template="/users/{user_id}",
        object_identifier_names=["user_id"],
        operations=["GET", "PUT", "DELETE"],
        has_read_operation=True,
        has_write_operation=True,
        has_delete_operation=True,
    )

    graph = build_security_graph([surface])

    vector = build_security_context_feature_vector(endpoint, graph)

    assert len(vector) == 28
    assert vector[:22] == extract_feature_vector(endpoint)
    assert vector[22:] == [
        1.0,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
    ]
