from api_discovery.models import APIObjectOperationSurface

from ai.graph_intelligence.models import (
    APIObjectNode,
    APIOperationEdge,
    APISecurityGraph,
)


def build_security_graph(
    surfaces: list[APIObjectOperationSurface],
) -> APISecurityGraph:
    """
    Build an in-memory API security graph from
    discovered object-operation surfaces.
    """

    objects: list[APIObjectNode] = []
    operations: list[APIOperationEdge] = []

    for surface in surfaces:
        objects.append(
            APIObjectNode(
                path_template=surface.path_template,
                object_identifier_names=(
                    surface.object_identifier_names.copy()
                ),
                target_method=surface.target_method,
            )
        )

        for method in surface.operations:
            operations.append(
                APIOperationEdge(
                    path_template=surface.path_template,
                    method=method,
                )
            )

    return APISecurityGraph(
        objects=objects,
        operations=operations,
    )
