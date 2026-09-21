from api_discovery.models import APIEndpoint, SecurityClassification
from risk_engine.features import (
    FEATURE_NAMES,
    calculate_path_depth,
    extract_feature_vector,
    extract_method_features,
    extract_risk_features,
)


def test_calculate_path_depth():
    assert calculate_path_depth("/health") == 1
    assert calculate_path_depth("/users") == 1
    assert calculate_path_depth("/users/{user_id}") == 2
    assert calculate_path_depth(
        "/admin/users/{user_id}/keys"
    ) == 4


def test_extract_method_features():
    assert extract_method_features("GET") == {
        "method_get": 1.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 0.0,
    }

    assert extract_method_features("DELETE") == {
        "method_get": 0.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 1.0,
    }


def test_extract_risk_features():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        parameters=[
            {
                "name": "user_id",
                "in": "path",
            },
            {
                "name": "password",
                "in": "query",
            },
        ],
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
        "parameter_count": 2.0,
        "path_depth": 2.0,
        "method_get": 0.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 1.0,
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
        "parameter_count": 0.0,
        "path_depth": 1.0,
        "method_get": 1.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 0.0,
    }


def test_feature_vector_order():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        parameters=[
            {
                "name": "user_id",
                "in": "path",
            },
            {
                "name": "password",
                "in": "query",
            },
        ],
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
        "parameter_count",
        "path_depth",
        "method_get",
        "method_post",
        "method_put",
        "method_patch",
        "method_delete",
    ]

    assert vector == [
        1.0,
        1.0,
        1.0,
        0.0,
        1.0,
        2.0,
        2.0,
        0.0,
        0.0,
        0.0,
        0.0,
        1.0,
    ]
