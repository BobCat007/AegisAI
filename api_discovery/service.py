from typing import Any

from api_discovery.models import APIInventory
from api_discovery.parser import parse_openapi_spec


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

    return APIInventory(
        title=title,
        version=version,
        openapi_version=str(openapi_version),
        total_endpoints=len(endpoints),
        endpoints=endpoints,
    )
