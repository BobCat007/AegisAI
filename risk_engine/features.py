from api_discovery.models import APIEndpoint


FEATURE_NAMES = [
    "is_authenticated",
    "is_destructive",
    "has_path_parameters",
    "is_authentication_endpoint",
    "has_sensitive_parameters",
    "parameter_count",
]


def extract_risk_features(
    endpoint: APIEndpoint,
) -> dict[str, float]:
    """
    Convert API security characteristics into numeric features.

    The returned dictionary keeps feature names explicit and readable.
    """

    classification = endpoint.security_classification

    return {
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
    }


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
