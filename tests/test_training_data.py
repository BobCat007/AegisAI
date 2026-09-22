from api_discovery.models import APIEndpoint, SecurityClassification
from scripts.generate_training_data import get_risk_label


def test_low_risk_label():
    endpoint = APIEndpoint(
        path="/health",
        method="GET",
        operation_category="read",
        security_classification=SecurityClassification(
            is_authenticated=True,
        ),
    )

    assert get_risk_label(endpoint) == "low"


def test_medium_risk_label():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        security_classification=SecurityClassification(
            is_authenticated=True,
            is_destructive=True,
            has_path_parameters=True,
        ),
    )

    assert get_risk_label(endpoint) == "medium"


def test_high_risk_label():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        security_classification=SecurityClassification(
            is_authenticated=True,
            is_destructive=True,
            has_path_parameters=True,
            has_sensitive_parameters=True,
            sensitive_parameters=["password"],
        ),
    )

    assert get_risk_label(endpoint) == "high"


def test_critical_risk_label():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        security_classification=SecurityClassification(
            is_destructive=True,
            has_path_parameters=True,
            has_sensitive_parameters=True,
            sensitive_parameters=["password"],
            is_authentication_endpoint=True,
        ),
    )

    assert get_risk_label(endpoint) == "critical"
