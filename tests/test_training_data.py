from api_discovery.models import APIEndpoint, SecurityClassification
from scripts.generate_training_data import (
    build_endpoint,
    generate_empty_response,
    get_risk_label,
)


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


def test_header_parameters_are_generated():
    endpoint = build_endpoint(
        path="/users",
        method="GET",
        operation_category="read",
        authenticated=True,
        header_parameter_count=2,
    )

    header_parameters = [
        parameter
        for parameter in endpoint.parameters
        if parameter.get("in") == "header"
    ]

    assert len(header_parameters) == 2


def test_empty_response_has_no_response_body():
    responses = generate_empty_response()

    endpoint = build_endpoint(
        path="/health/check",
        method="GET",
        operation_category="read",
        authenticated=False,
        responses=responses,
    )

    assert endpoint.responses == responses
    assert endpoint.responses["204"].get("content") is None
