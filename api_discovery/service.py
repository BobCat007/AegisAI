from typing import Any

from api_discovery.parser import parse_openapi_spec

from api_discovery.models import (
    APIEndpoint,
    APIInventory,
    APIObjectOperationSurface,
)

def build_object_operation_surfaces(
    endpoints: list[APIEndpoint],
) -> list[APIObjectOperationSurface]:
    
    """
    Group object-specific endpoints by their path template.

    Example:

        /orders/{order_id}
            GET
            PUT
            DELETE

    becomes one object operation surface.
    """

    surfaces: dict[str, APIObjectOperationSurface] = {}

    for endpoint in endpoints:
        classification = endpoint.security_classification

        if not classification.object_identifier_names:
            continue

        path_template = endpoint.path

        if path_template not in surfaces:
            surfaces[path_template] = APIObjectOperationSurface(
                path_template=path_template,
                object_identifier_names=(
                    classification.object_identifier_names.copy()
                ),
                operations=[],
            )

        surface = surfaces[path_template]

        if endpoint.method not in surface.operations:
            surface.operations.append(endpoint.method)

    for surface in surfaces.values():
        surface.has_read_operation = "GET" in surface.operations

        surface.has_write_operation = any(
            method in surface.operations
            for method in {
                "POST",
                "PUT",
                "PATCH",
            }
        )

        surface.has_delete_operation = (
            "DELETE" in surface.operations
        )

    return list(surfaces.values())

def discover_api(spec: dict[str, Any]) -> APIInventory:
    """
    Discover and normalize API information from an OpenAPI specification.
    """

    info = spec.get("info", {})

    title = info.get("title", "Unknown API")
    version = info.get("version", "Unknown")

    openapi_version = spec.get(
        "openapi",
        spec.get("swagger", "Unknown"),
    )

    endpoints = parse_openapi_spec(spec)

    object_operation_surfaces = build_object_operation_surfaces(
        endpoints
    )

    return APIInventory(
        title=title,
        version=version,
        openapi_version=str(openapi_version),
        total_endpoints=len(endpoints),
        endpoints=endpoints,
        object_operation_surfaces=object_operation_surfaces,
    )
