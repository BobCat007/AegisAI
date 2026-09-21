from api_discovery.models import APIEndpoint, SecurityClassification
from risk_engine.features import (
    FEATURE_NAMES,
    extract_feature_vector,
    extract_risk_features,
)


def test_extract_risk_features():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        security_classification=SecurityClassification(
            is_authenticated=True,
            is_destructive=True,
            has_path_parameters=True,
            is_authentication_endpoint=False,
            has_sensitive_parameters=True,
            sensitive_parameters=["password"],
        ),
    )

    features = extract_risk_features(endpoint)

    assert features == {
        "is_authenticated": 1.0,
        "is_destructive": 1.0,
        "has_path_parameters": 1.0,
        "is_authentication_endpoint": 0.0,
        "has_sensitive_parameters": 1.0,
    }


def test_extract_features_from_low_risk_endpoint():
    endpoint = APIEndpoint(
        path="/health",
        method="GET",
        operation_category="read",
        security_classification=SecurityClassification(
            is_authenticated=True,
        ),
    )

    features = extract_risk_features(endpoint)

    assert features == {
        "is_authenticated": 1.0,
        "is_destructive": 0.0,
        "has_path_parameters": 0.0,
        "is_authentication_endpoint": 0.0,
        "has_sensitive_parameters": 0.0,
    }


def test_feature_vector_order():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        security_classification=SecurityClassification(
            is_authenticated=True,
            is_destructive=True,
            has_path_parameters=True,
            is_authentication_endpoint=False,
            has_sensitive_parameters=True,
        ),
    )

    vector = extract_feature_vector(endpoint)

    assert FEATURE_NAMES == [
        "is_authenticated",
        "is_destructive",
        "has_path_parameters",
        "is_authentication_endpoint",
        "has_sensitive_parameters",
    ]

    assert vector == [1.0, 1.0, 1.0, 0.0, 1.0]
