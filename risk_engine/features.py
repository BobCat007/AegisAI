from typing import Any

from api_discovery.models import APIEndpoint
from risk_engine.schema import FEATURE_NAMES


HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
]


def calculate_path_depth(path: str) -> int:
    """
    Calculate the number of meaningful path segments.

    Example:
        /health -> 1
        /users/{user_id} -> 2
        /admin/users/{user_id}/keys -> 4
    """

    return len(
        [
            segment
            for segment in path.strip("/").split("/")
            if segment
        ]
    )


def extract_method_features(
    method: str,
) -> dict[str, float]:
    """
    Convert an HTTP method into one-hot encoded features.
    """

    normalized_method = method.upper()

    return {
        f"method_{http_method.lower()}": float(
            normalized_method == http_method
        )
        for http_method in HTTP_METHODS
    }


def extract_parameter_location_features(
    endpoint: APIEndpoint,
) -> dict[str, float]:
    """
    Count parameters according to their location.
    """

    counts = {
        "path_parameter_count": 0.0,
        "query_parameter_count": 0.0,
        "header_parameter_count": 0.0,
    }

    for parameter in endpoint.parameters:
        if not isinstance(parameter, dict):
            continue

        location = parameter.get("in")

        if location == "path":
            counts["path_parameter_count"] += 1.0
        elif location == "query":
            counts["query_parameter_count"] += 1.0
        elif location == "header":
            counts["header_parameter_count"] += 1.0

    return counts


def calculate_request_body_property_count(
    request_body: dict[str, Any] | None,
) -> int:
    """
    Count top-level properties in the request body schema.

    The function checks the first available media type under
    requestBody.content and counts properties defined directly
    on its schema.

    Returns 0 when the request body or schema does not define
    object properties.
    """

    if not isinstance(request_body, dict):
        return 0

    content = request_body.get("content")

    if not isinstance(content, dict):
        return 0

    for media_type in content.values():
        if not isinstance(media_type, dict):
            continue

        schema = media_type.get("schema")

        if not isinstance(schema, dict):
            continue

        properties = schema.get("properties")

        if isinstance(properties, dict):
            return len(properties)

    return 0


def calculate_request_body_required_property_count(
    request_body: dict[str, Any] | None,
) -> int:
    """
    Count top-level required properties in the request body schema.

    Returns 0 when the request body, schema, or required list
    is not present.
    """

    if not isinstance(request_body, dict):
        return 0

    content = request_body.get("content")

    if not isinstance(content, dict):
        return 0

    for media_type in content.values():
        if not isinstance(media_type, dict):
            continue

        schema = media_type.get("schema")

        if not isinstance(schema, dict):
            continue

        required = schema.get("required")

        if isinstance(required, list):
            return len(
                [
                    property_name
                    for property_name in required
                    if isinstance(property_name, str)
                ]
            )

    return 0


def calculate_request_body_max_depth(
    request_body: dict[str, Any] | None,
) -> int:
    """
    Calculate the maximum nesting depth of an object schema.

    A schema with direct properties has depth 1.

    Example:

        {
            "user": {
                "name": "..."
            }
        }

    has depth 2.

    Returns 0 when the request body does not define an
    object schema with properties.
    """

    if not isinstance(request_body, dict):
        return 0

    content = request_body.get("content")

    if not isinstance(content, dict):
        return 0

    for media_type in content.values():
        if not isinstance(media_type, dict):
            continue

        schema = media_type.get("schema")

        if not isinstance(schema, dict):
            continue

        return _calculate_schema_depth(schema)

    return 0


def _calculate_schema_depth(
    schema: dict[str, Any],
) -> int:
    """
    Recursively calculate the maximum depth of an object schema.
    """

    properties = schema.get("properties")

    if not isinstance(properties, dict) or not properties:
        return 0

    max_child_depth = 0

    for property_schema in properties.values():
        if not isinstance(property_schema, dict):
            continue

        child_depth = _calculate_schema_depth(
            property_schema
        )

        max_child_depth = max(
            max_child_depth,
            child_depth,
        )

    return 1 + max_child_depth


def has_response_body(
    responses: dict[str, Any] | None,
) -> bool:
    """
    Determine whether an endpoint defines at least one response
    containing a response body.

    A response is considered to have a body when its definition
    contains a non-empty content object.
    """

    if not isinstance(responses, dict):
        return False

    for response in responses.values():
        if not isinstance(response, dict):
            continue

        content = response.get("content")

        if isinstance(content, dict) and content:
            return True

    return False


def calculate_response_body_property_count(
    responses: dict[str, Any] | None,
) -> int:
    """
    Count top-level properties in the first available response
    body schema.

    The function checks response definitions for a non-empty
    content object, then checks the first available media type
    and counts properties defined directly on its schema.

    Returns 0 when no response body or object properties
    are defined.
    """

    if not isinstance(responses, dict):
        return 0

    for response in responses.values():
        if not isinstance(response, dict):
            continue

        content = response.get("content")

        if not isinstance(content, dict):
            continue

        for media_type in content.values():
            if not isinstance(media_type, dict):
                continue

            schema = media_type.get("schema")

            if not isinstance(schema, dict):
                continue

            properties = schema.get("properties")

            if isinstance(properties, dict):
                return len(properties)

    return 0


def calculate_response_body_max_depth(
    responses: dict[str, Any] | None,
) -> int:
    """
    Calculate the maximum nesting depth of the first available
    response body schema.

    A schema with direct properties has depth 1.

    Example:

        {
            "user": {
                "profile": {
                    "name": "..."
                }
            }
        }

    has depth 3.

    Returns 0 when no response body or object properties
    are defined.
    """

    if not isinstance(responses, dict):
        return 0

    for response in responses.values():
        if not isinstance(response, dict):
            continue

        content = response.get("content")

        if not isinstance(content, dict):
            continue

        for media_type in content.values():
            if not isinstance(media_type, dict):
                continue

            schema = media_type.get("schema")

            if not isinstance(schema, dict):
                continue

            return _calculate_schema_depth(schema)

    return 0


def extract_risk_features(
    endpoint: APIEndpoint,
) -> dict[str, float]:
    """
    Convert API security characteristics into numeric features.

    The returned dictionary keeps feature names explicit and readable.
    """

    classification = endpoint.security_classification

    features = {
        "is_authenticated": float(
            classification.is_authenticated
        ),
        "is_destructive": float(
            classification.is_destructive
        ),
        "has_path_parameters": float(
            classification.has_path_parameters
        ),
        "is_authentication_endpoint": float(
            classification.is_authentication_endpoint
        ),
        "has_sensitive_parameters": float(
            classification.has_sensitive_parameters
        ),
        "parameter_count": float(
            len(endpoint.parameters)
        ),
        "path_depth": float(
            calculate_path_depth(endpoint.path)
        ),
        "has_request_body": float(
            endpoint.request_body is not None
        ),
        "request_body_property_count": float(
            calculate_request_body_property_count(
                endpoint.request_body
            )
        ),
        "request_body_required_property_count": float(
            calculate_request_body_required_property_count(
                endpoint.request_body
            )
        ),
        "request_body_max_depth": float(
            calculate_request_body_max_depth(
                endpoint.request_body
            )
        ),
        "has_response_body": float(
            has_response_body(endpoint.responses)
        ),
        "response_body_property_count": float(
            calculate_response_body_property_count(
                endpoint.responses
            )
        ),
        "response_body_max_depth": float(
            calculate_response_body_max_depth(
                endpoint.responses
            )
        ),
    }

    features.update(
        extract_parameter_location_features(endpoint)
    )

    features.update(
        extract_method_features(endpoint.method)
    )

    return features


def extract_feature_vector(
    endpoint: APIEndpoint,
) -> list[float]:
    """
    Convert an API endpoint into an ordered numeric feature vector.

    The order is defined by the central feature schema and must remain
    stable when the features are later used by a machine-learning model.
    """

    features = extract_risk_features(endpoint)

    return [
        features[name]
        for name in FEATURE_NAMES
    ]
