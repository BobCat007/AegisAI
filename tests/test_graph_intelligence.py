from api_discovery.models import APIObjectOperationSurface

from ai.graph_intelligence.builder import build_security_graph
from ai.graph_intelligence.models import (
    APIObjectNode,
    APIOperationEdge,
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


def test_build_empty_security_graph():
    graph = build_security_graph([])

    assert graph.objects == []
    assert graph.operations == []
