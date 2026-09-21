from api_discovery.models import APIEndpoint, SecurityClassification
from risk_engine.scorer import calculate_risk


def test_low_risk_endpoint():
    endpoint = APIEndpoint(
        path="/health",
        method="GET",
        operation_category="read",
        security_classification=SecurityClassification(
            is_authenticated=True,
        ),
    )

    assessment = calculate_risk(endpoint)

    assert assessment.score == 0
    assert assessment.severity == "low"
    assert assessment.reasons == []

    assert len(assessment.risk_factors) == 5
    assert all(
        factor.triggered is False
        for factor in assessment.risk_factors
    )


def test_medium_risk_endpoint():
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

    assessment = calculate_risk(endpoint)

    assert assessment.score == 50
    assert assessment.severity == "medium"
    assert "Destructive operation" in assessment.reasons
    assert "Object identifier in path" in assessment.reasons

    factors = {
        factor.name: factor
        for factor in assessment.risk_factors
    }

    assert factors["destructive_operation"].triggered is True
    assert factors["destructive_operation"].weight == 30

    assert factors["object_identifier"].triggered is True
    assert factors["object_identifier"].weight == 20

    assert factors["sensitive_parameter"].triggered is False
    assert factors["authentication_endpoint"].triggered is False
    assert factors["missing_authentication"].triggered is False


def test_high_risk_endpoint():
    endpoint = APIEndpoint(
        path="/auth/login",
        method="POST",
        operation_category="create/action",
        security_classification=SecurityClassification(
            is_authentication_endpoint=True,
            has_sensitive_parameters=True,
            sensitive_parameters=["password"],
        ),
    )

    assessment = calculate_risk(endpoint)

    assert assessment.score == 50
    assert assessment.severity == "medium"
    assert "Sensitive parameter detected" in assessment.reasons
    assert "Authentication-related endpoint" in assessment.reasons
    assert "Endpoint does not require authentication" in assessment.reasons

    factors = {
        factor.name: factor
        for factor in assessment.risk_factors
    }

    assert factors["sensitive_parameter"].triggered is True
    assert factors["sensitive_parameter"].weight == 25

    assert factors["authentication_endpoint"].triggered is True
    assert factors["authentication_endpoint"].weight == 15

    assert factors["missing_authentication"].triggered is True
    assert factors["missing_authentication"].weight == 10


def test_critical_risk_endpoint():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        security_classification=SecurityClassification(
            is_destructive=True,
            has_path_parameters=True,
            has_sensitive_parameters=True,
            sensitive_parameters=["token"],
            is_authentication_endpoint=True,
        ),
    )

    assessment = calculate_risk(endpoint)

    assert assessment.score == 100
    assert assessment.severity == "critical"

    factors = {
        factor.name: factor
        for factor in assessment.risk_factors
    }

    assert factors["destructive_operation"].triggered is True
    assert factors["object_identifier"].triggered is True
    assert factors["sensitive_parameter"].triggered is True
    assert factors["authentication_endpoint"].triggered is True
    assert factors["missing_authentication"].triggered is True
