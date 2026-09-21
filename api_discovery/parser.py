from typing import Any

from api_discovery.models import APIEndpoint


HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}


def parse_openapi_spec(spec: dict[str, Any]) -> list[APIEndpoint]:
    """
    Parse an OpenAPI specification and extract API endpoints.
    """

    endpoints: list[APIEndpoint] = []

    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        path_parameters = path_item.get("parameters", [])

        for method, operation in path_item.items():
            method_lower = method.lower()

            if method_lower not in HTTP_METHODS:
                continue

            if not isinstance(operation, dict):
                continue

            operation_parameters = operation.get("parameters", [])

            parameters = [
                *path_parameters,
                *operation_parameters,
            ]

            endpoint = APIEndpoint(
                path=path,
                method=method_lower.upper(),
                operation_id=operation.get("operationId"),
                summary=operation.get("summary"),
                description=operation.get("description"),
                tags=operation.get("tags", []),
                parameters=parameters,
                request_body=operation.get("requestBody"),
                security=operation.get(
                    "security",
                    spec.get("security", []),
                ),
            )

            endpoints.append(endpoint)

    return endpoints
