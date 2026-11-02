from ai.security_reasoning.engine import SecurityReasoningEngine
from ai.security_reasoning.remediation import RemediationEngine
from api_discovery.models import APIEndpoint, SecurityClassification


def make_endpoint(
    path="/users/{user_id}",
    method="GET",
    object_identifiers=None,
    destructive=False,
    sensitive_response_fields=None,
):
    object_identifiers = object_identifiers or []
    sensitive_response_fields = sensitive_response_fields or []

    classification = SecurityClassification(
        is_authenticated=True,
        is_destructive=destructive,
        has_path_parameters=bool(object_identifiers),
        object_identifier_names=object_identifiers,
        object_access_pattern=(
            "object" if object_identifiers else "collection"
        ),
        has_sensitive_response_fields=bool(sensitive_response_fields),
        sensitive_response_fields=sensitive_response_fields,
    )

    return APIEndpoint(
        path=path,
        method=method,
        operation_category="read",
        security_classification=classification,
    )


def test_bola_finding_generates_object_authorization_remediation():
    reasoning = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(object_identifiers=["user_id"])
    )

    plan = RemediationEngine().generate(reasoning)

    assert plan.total_recommendations == 1

    recommendation = plan.recommendations[0]

    assert recommendation.finding_id == "BOLA-REVIEW"
    assert recommendation.category == "bola_review"
    assert recommendation.remediation_steps
    assert recommendation.validation_steps
    assert recommendation.endpoint == "GET /users/{user_id}"


def test_destructive_findings_generate_specific_remediation():
    reasoning = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(
            method="DELETE",
            destructive=True,
        )
    )

    plan = RemediationEngine().generate(reasoning)

    categories = {
        item.category
        for item in plan.recommendations
    }

    assert "bfla_review" in categories
    assert "destructive_operation_review" in categories


def test_sensitive_data_finding_generates_data_minimization_steps():
    reasoning = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(
            path="/users/profile",
            sensitive_response_fields=["access_token"],
        )
    )

    plan = RemediationEngine().generate(reasoning)

    recommendation = plan.recommendations[0]

    assert recommendation.category == "sensitive_data_review"
    assert any(
        "response schemas" in step.lower()
        or "response" in step.lower()
        for step in recommendation.remediation_steps
    )


def test_remediation_preserves_finding_evidence_traceability():
    reasoning = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(object_identifiers=["user_id"])
    )

    plan = RemediationEngine().generate(reasoning)

    recommendation = plan.recommendations[0]

    assert recommendation.finding_id == "BOLA-REVIEW"
    assert recommendation.evidence_sources
    assert recommendation.evidence_references


def test_empty_findings_produce_empty_remediation_plan():
    reasoning = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(
            path="/health",
            object_identifiers=[],
        )
    )

    plan = RemediationEngine().generate(reasoning)

    assert plan.total_recommendations == 0
    assert plan.recommendations == []


def test_remediation_does_not_confirm_vulnerabilities():
    reasoning = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(object_identifiers=["user_id"])
    )

    plan = RemediationEngine().generate(reasoning)

    assert plan.total_recommendations > 0

    for recommendation in plan.recommendations:
        assert recommendation.limitations
        assert recommendation.finding_id
