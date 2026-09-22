from ai.graph_intelligence.models import APISecurityGraph


def count_objects_with_full_operation_surface(
    graph: APISecurityGraph,
) -> int:
    """
    Count API objects that expose read, write, and delete operations.
    """

    full_surface_objects = 0

    for obj in graph.objects:
        methods = {
            operation.method
            for operation in graph.operations
            if operation.path_template == obj.path_template
        }

        has_read = "GET" in methods
        has_write = bool(
            methods.intersection({"POST", "PUT", "PATCH"})
        )
        has_delete = "DELETE" in methods

        if has_read and has_write and has_delete:
            full_surface_objects += 1

    return full_surface_objects
