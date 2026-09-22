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


def count_objects_with_mutation_without_read(
    graph: APISecurityGraph,
) -> int:
    """
    Count API objects that expose write or delete operations
    without exposing a GET operation.
    """

    mutation_without_read_objects = 0

    for obj in graph.objects:
        methods = {
            operation.method
            for operation in graph.operations
            if operation.path_template == obj.path_template
        }

        has_read = "GET" in methods
        has_mutation = bool(
            methods.intersection(
                {"POST", "PUT", "PATCH", "DELETE"}
            )
        )

        if has_mutation and not has_read:
            mutation_without_read_objects += 1

    return mutation_without_read_objects


def count_objects_with_delete_without_read(
    graph: APISecurityGraph,
) -> int:
    """
    Count API objects that expose DELETE without exposing GET.
    """

    delete_without_read_objects = 0

    for obj in graph.objects:
        methods = {
            operation.method
            for operation in graph.operations
            if operation.path_template == obj.path_template
        }

        has_read = "GET" in methods
        has_delete = "DELETE" in methods

        if has_delete and not has_read:
            delete_without_read_objects += 1

    return delete_without_read_objects


def count_objects_with_write_without_read(
    graph: APISecurityGraph,
) -> int:
    """
    Count API objects that expose POST, PUT, or PATCH
    without exposing a GET operation.
    """

    write_without_read_objects = 0

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

        if has_write and not has_read:
            write_without_read_objects += 1

    return write_without_read_objects


def count_objects_with_multiple_mutation_types(
    graph: APISecurityGraph,
) -> int:
    """
    Count API objects that expose more than one distinct
    mutation method.
    """

    multiple_mutation_objects = 0

    mutation_methods = {"POST", "PUT", "PATCH", "DELETE"}

    for obj in graph.objects:
        methods = {
            operation.method
            for operation in graph.operations
            if operation.path_template == obj.path_template
        }

        mutation_types = methods.intersection(mutation_methods)

        if len(mutation_types) > 1:
            multiple_mutation_objects += 1

    return multiple_mutation_objects


def count_objects_with_write_and_delete_without_read(
    graph: APISecurityGraph,
) -> int:
    """
    Count API objects that expose both write and delete operations
    without exposing a GET operation.
    """

    write_and_delete_without_read_objects = 0

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

        if has_write and has_delete and not has_read:
            write_and_delete_without_read_objects += 1

    return write_and_delete_without_read_objects

def get_target_operation_methods(
    graph: APISecurityGraph,
) -> set[str]:
    """
    Return the HTTP methods exposed by the object containing
    the target operation.

    If no target operation is defined, return an empty set.
    """

    for obj in graph.objects:
        if obj.target_method is None:
            continue

        return {
            operation.method
            for operation in graph.operations
            if operation.path_template == obj.path_template
        }

    return set()

def has_target_delete_without_read(
    graph: APISecurityGraph,
) -> bool:
    """
    Return True when the target operation is DELETE and
    the same object does not expose a GET operation.
    """

    target_method = None

    for obj in graph.objects:
        if obj.target_method is not None:
            target_method = obj.target_method
            break

    if target_method != "DELETE":
        return False

    methods = get_target_operation_methods(graph)

    return "GET" not in methods

def extract_target_graph_features(
    graph: APISecurityGraph,
) -> dict[str, int]:
    """
    Extract graph features specific to the target operation.
    """

    return {
        "target_delete_without_read": int(
            has_target_delete_without_read(graph)
        ),
    }

def extract_graph_features(
    graph: APISecurityGraph,
) -> dict[str, int]:
    """
    Extract the complete graph-level security feature set.
    """

    return {
        "objects_with_full_operation_surface": (
            count_objects_with_full_operation_surface(graph)
        ),
        "objects_with_mutation_without_read": (
            count_objects_with_mutation_without_read(graph)
        ),
        "objects_with_delete_without_read": (
            count_objects_with_delete_without_read(graph)
        ),
        "objects_with_write_without_read": (
            count_objects_with_write_without_read(graph)
        ),
        "objects_with_multiple_mutation_types": (
            count_objects_with_multiple_mutation_types(graph)
        ),
        "objects_with_write_and_delete_without_read": (
            count_objects_with_write_and_delete_without_read(graph)
        ),
    }
