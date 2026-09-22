from api_discovery.models import APIObjectOperationSurface

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
)

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
