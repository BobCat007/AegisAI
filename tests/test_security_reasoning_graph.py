from ai.security_reasoning.engine import SecurityReasoningEngine
from api_discovery.models import (
    APIEndpoint,
    APIObjectOperationSurface,
    SecurityClassification,
)


def make_endpoint(path="/users/{user_id}", method="DELETE"):
    classification = SecurityClassification(
        is_authenticated=True,
        is_destructive=method in {"DELETE", "PUT", "PATCH"},
        has_path_parameters=True,
        object_identifier_names=["user_id"],
        object_access_pattern="object",
    )

    return APIEndpoint(
        path=path,
        method=method,
        operation_category="write",
        security_classification=classification,
    )


def make_surface(path, operations):
    return APIObjectOperationSurface(
        path_template=path,
        object_identifier_names=["user_id"],
        operations=operations,
    )


def test_graph_mutation_without_read_creates_review_finding():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint()

    surfaces = [
        make_surface("/users/{user_id}", ["PUT", "DELETE"]),
    ]

    result = engine.analyze_endpoint(
        endpoint,
        object_surfaces=surfaces,
    )

    categories = {finding.category for finding in result.findings}

    assert "mutation_without_read_review" in categories
    assert "delete_without_read_review" in categories
    assert result.vulnerabilities_confirmed is False


def test_graph_multiple_mutation_types_creates_finding():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint(method="PUT")

    surfaces = [
        make_surface(
            "/users/{user_id}",
            ["GET", "POST", "PUT", "PATCH"],
        ),
    ]

    result = engine.analyze_endpoint(
        endpoint,
        object_surfaces=surfaces,
    )

    assert any(
        finding.category == "multiple_mutation_types_review"
        for finding in result.findings
    )


def test_graph_evidence_is_matched_by_exact_path_template():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint()

    surfaces = [
        make_surface("/orders/{order_id}", ["POST", "DELETE"]),
    ]

    result = engine.analyze_endpoint(
        endpoint,
        object_surfaces=surfaces,
    )

    graph_categories = {
        "mutation_without_read_review",
        "delete_without_read_review",
        "multiple_mutation_types_review",
    }

    assert not any(
        finding.category in graph_categories
        for finding in result.findings
    )


def test_graph_read_operation_prevents_mutation_without_read_finding():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint()

    surfaces = [
        make_surface(
            "/users/{user_id}",
            ["GET", "PUT", "DELETE"],
        ),
    ]

    result = engine.analyze_endpoint(
        endpoint,
        object_surfaces=surfaces,
    )

    assert all(
        finding.category != "mutation_without_read_review"
        for finding in result.findings
    )

    assert all(
        finding.category != "delete_without_read_review"
        for finding in result.findings
    )


def test_graph_findings_include_traceable_operation_evidence():
    engine = SecurityReasoningEngine()
    endpoint = make_endpoint()

    surfaces = [
        make_surface("/users/{user_id}", ["PUT", "DELETE"]),
    ]

    result = engine.analyze_endpoint(
        endpoint,
        object_surfaces=surfaces,
    )

    graph_finding = next(
        finding
        for finding in result.findings
        if finding.category == "mutation_without_read_review"
    )

    assert graph_finding.evidence

    sources = {item.source for item in graph_finding.evidence}

    assert "API security graph" in sources

    assert all(
        item.reference == "/users/{user_id}"
        for item in graph_finding.evidence
    )

    assert graph_finding.recommended_validation
