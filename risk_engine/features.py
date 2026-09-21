from api_discovery.models import APIEndpoint


HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
]


FEATURE_NAMES = [
    "is_authenticated",
    "is_destructive",
    "has_path_parameters",
    "is_authentication_endpoint",
    "has_sensitive_parameters",
    "parameter_count",
    "path_depth",
    "has_request_body",
    "path_parameter_count",
    "query_parameter_count",
    "header_parameter_count",
    "method_get",
    "method_post",
    "method_put",
    "method_patch",
    "method_delete",
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

    The order is defined by FEATURE_NAMES and must remain stable
    when the features are later used by a machine-learning model.
    """

    features = extract_risk_features(endpoint)

    return [
        features[name]
        for name in FEATURE_NAMES
    ]
