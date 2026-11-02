from ai.risk_prediction.evidence import SecurityEvidence
from ai.security_reasoning.engine import SecurityReasoningEngine
from api_discovery.models import APIEndpoint, SecurityClassification


def make_endpoint(
    *,
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


def test_object_identifier_triggers_bola_review():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        object_identifiers=["user_id"],
    )

    result = engine.analyze_endpoint(endpoint)

    assert result.overall_assessment == "review_recommended"
    assert result.vulnerabilities_confirmed is False
    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.category == "bola_review"
    assert finding.validation_status == "not_validated"
    assert "user_id" in finding.evidence[0].detail
    assert finding.recommended_validation


def test_destructive_endpoint_triggers_bfla_and_safeguard_reviews():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        method="DELETE",
        destructive=True,
    )

    result = engine.analyze_endpoint(endpoint)

    categories = {finding.category for finding in result.findings}

    assert "bfla_review" in categories
    assert "destructive_operation_review" in categories
    assert result.vulnerabilities_confirmed is False


def test_sensitive_response_fields_trigger_sensitive_data_review():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        path="/users/profile",
        method="GET",
        sensitive_response_fields=["access_token", "refresh_token"],
    )

    result = engine.analyze_endpoint(endpoint)

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.category == "sensitive_data_review"
    assert finding.severity == "high"
    assert "access_token" in finding.evidence[0].detail
    assert "refresh_token" in finding.evidence[0].detail


def test_exact_documented_evidence_match_is_reported():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        path="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        object_identifiers=["vehicleId"],
    )

    evidence = SecurityEvidence(
        source="OWASP crAPI",
        vulnerability_type="BOLA",
        path="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        description="Documented object-level authorization issue.",
        confidence="documented",
        references=["OWASP crAPI"],
    )

    result = engine.analyze_endpoint(
        endpoint,
        documented_evidence=[evidence],
    )

    documented_findings = [
        finding
        for finding in result.findings
        if finding.category == "documented_vulnerability_reference"
    ]

    assert result.overall_assessment == "documented_reference_match"
    assert len(documented_findings) == 1
    assert (
        documented_findings[0].validation_status
        == "documented_reference"
    )
    assert result.vulnerabilities_confirmed is False


def test_documented_evidence_requires_exact_path_and_method_match():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        path="/users/{user_id}",
        method="GET",
        object_identifiers=["user_id"],
    )

    evidence = SecurityEvidence(
        source="OWASP crAPI",
        vulnerability_type="BOLA",
        path="/users/{user_id}",
        method="DELETE",
        description="Documented delete authorization issue.",
    )

    result = engine.analyze_endpoint(
        endpoint,
        documented_evidence=[evidence],
    )

    assert result.overall_assessment == "review_recommended"
    assert all(
        finding.category != "documented_vulnerability_reference"
        for finding in result.findings
    )


def test_endpoint_without_review_signals_returns_empty_findings():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        path="/health",
        method="GET",
    )

    result = engine.analyze_endpoint(endpoint)

    assert result.overall_assessment == "no_review_signal"
    assert result.findings == []
    assert result.vulnerabilities_confirmed is False
    assert result.path == "/health"
    assert result.method == "GET"


def test_documented_evidence_method_matching_is_case_insensitive():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        path="/users/{user_id}",
        method="GET",
        object_identifiers=["user_id"],
    )

    evidence = SecurityEvidence(
        source="Test catalog",
        vulnerability_type="BOLA",
        path="/users/{user_id}",
        method="get",
        description="Test documented reference.",
    )

    result = engine.analyze_endpoint(
        endpoint,
        documented_evidence=[evidence],
    )

    assert result.overall_assessment == "documented_reference_match"


def test_multiple_rules_can_produce_multiple_findings():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(
        path="/users/{user_id}",
        method="DELETE",
        object_identifiers=["user_id"],
        destructive=True,
        sensitive_response_fields=["access_token"],
    )

    result = engine.analyze_endpoint(endpoint)

    categories = {finding.category for finding in result.findings}

    assert categories == {
        "bola_review",
        "bfla_review",
        "destructive_operation_review",
        "sensitive_data_review",
    }
    assert len(result.findings) == 4
    assert result.vulnerabilities_confirmed is False
