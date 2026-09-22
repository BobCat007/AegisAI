from api_discovery.models import APIObjectOperationSurface


def build_graph_scenarios() -> list[list[APIObjectOperationSurface]]:
    """
    Build controlled API object-operation graph scenarios.

    Each scenario represents a different API-wide operation structure.
    Endpoint-level risk labels remain independent of these scenarios.
    """

    return [
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["GET"],
                has_read_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["GET", "POST", "PUT"],
                has_read_operation=True,
                has_write_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["POST"],
                has_write_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["DELETE"],
                has_delete_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["PUT", "DELETE"],
                has_write_operation=True,
                has_delete_operation=True,
            ),
        ],
        [
            APIObjectOperationSurface(
                path_template="/users/{user_id}",
                object_identifier_names=["user_id"],
                operations=["GET", "PUT", "DELETE"],
                has_read_operation=True,
                has_write_operation=True,
                has_delete_operation=True,
            ),
            APIObjectOperationSurface(
                path_template="/orders/{order_id}",
                object_identifier_names=["order_id"],
                operations=["GET", "PUT"],
                has_read_operation=True,
                has_write_operation=True,
            ),
        ],
    ]
