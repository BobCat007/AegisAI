from api_discovery.models import APIObjectOperationSurface


def build_graph_scenarios() -> list[list[APIObjectOperationSurface]]:
    """
    Build controlled API object-operation graph scenarios.

    Each scenario represents the operation structure around a
    specific target operation on an API object.
    """

    return [
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["GET"],
                target_method="GET",
                has_read_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["GET", "POST", "PUT"],
                target_method="PUT",
                has_read_operation=True,
                has_write_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["POST"],
                target_method="POST",
                has_write_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["DELETE"],
                target_method="DELETE",
                has_delete_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["PUT", "DELETE"],
                target_method="DELETE",
                has_write_operation=True,
                has_delete_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["GET", "PUT", "DELETE"],
                target_method="DELETE",
                has_read_operation=True,
                has_write_operation=True,
                has_delete_operation=True,
            ),
            APIObjectOperationSurface(
                path_template="/orders/{order_id}",
                object_identifier_names=["order_id"],
                operations=["GET", "PUT"],
                target_method=None,
                has_read_operation=True,
                has_write_operation=True,
            ),
        ],
    ]
