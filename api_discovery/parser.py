from typing import Any

from api_discovery.models import APIEndpoint, SecurityClassification


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


SENSITIVE_PARAMETER_NAMES = {
    "password",
    "passwd",
    "pass",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "client_secret",
}


def classify_endpoint(
    path: str,
    method: str,
    security: list[dict[str, Any]],
    parameters: list[dict[str, Any]],
) -> SecurityClassification:
    """
    Classify an API endpoint using security characteristics.
    """

    indicators: list[str] = []

    is_authenticated = bool(security)
    is_destructive = method in {"DELETE", "PUT", "PATCH"}
    has_path_parameters = "{" in path and "}" in path

    path_lower = path.lower()

    authentication_keywords = {
        "auth",
        "login",
        "signin",
        "sign-in",
        "logout",
        "register",
        "signup",
        "sign-up",
        "token",
        "oauth",
    }

    is_authentication_endpoint = any(
        keyword in path_lower
        for keyword in authentication_keywords
    )

    sensitive_parameters: list[str] = []

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue

        parameter_name = parameter.get("name")

        if not isinstance(parameter_name, str):
            continue

        normalized_name = parameter_name.lower().strip()

        if normalized_name in SENSITIVE_PARAMETER_NAMES:
            sensitive_parameters.append(parameter_name)

    has_sensitive_parameters = bool(sensitive_parameters)

    if is_authenticated:
        indicators.append("Authentication required")

    if is_destructive:
        indicators.append("Destructive operation")

    if has_path_parameters:
        indicators.append("Object identifier in path")

    if is_authentication_endpoint:
        indicators.append("Authentication-related endpoint")

    if has_sensitive_parameters:
        indicators.append("Sensitive parameter detected")

    return SecurityClassification(
        is_authenticated=is_authenticated,
        is_destructive=is_destructive,
        has_path_parameters=has_path_parameters,
        is_authentication_endpoint=is_authentication_endpoint,
        has_sensitive_parameters=has_sensitive_parameters,
        sensitive_parameters=sensitive_parameters,
        risk_indicators=indicators,
    )


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

            security = operation.get(
                "security",
                spec.get("security", []),
            )

            security_classification = classify_endpoint(
                path=path,
                method=method_lower.upper(),
                security=security,
                parameters=parameters,
            )

            endpoint = APIEndpoint(
                path=path,
                method=method_lower.upper(),
                operation_id=operation.get("operationId"),
                summary=operation.get("summary"),
                description=operation.get("description"),
                tags=operation.get("tags", []),
                parameters=parameters,
                request_body=operation.get("requestBody"),
                security=security,
                security_classification=security_classification,
            )

            endpoints.append(endpoint)

    return endpoints
