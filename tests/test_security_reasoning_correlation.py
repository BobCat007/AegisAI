import pytest

from ai.security_reasoning.correlation import EvidenceCorrelationEngine
from ai.security_reasoning.models import EvidenceSource


@pytest.fixture
def engine():
    return EvidenceCorrelationEngine()


def test_independent_sources_support_each_other(engine):
    evidence = [
        EvidenceSource(
            source_id="structure-1",
            source_type="api_structure",
            scope="endpoint",
            detail="Endpoint accepts an object identifier.",
            reference="GET /api/items/{item_id}",
            indicator="object_identifier",
        ),
        EvidenceSource(
            source_id="graph-1",
            source_type="security_graph",
            scope="endpoint",
            detail="Graph identifies an object operation.",
            reference="GET /api/items/{item_id}",
            indicator="object_operation",
        ),
    ]

    result = engine.correlate(evidence)

    assert len(result.groups) == 1
    assert len(result.relationships) == 1
    assert result.relationships[0].relationship == "supports"
    assert result.relationships[0].independent_sources is True
    assert result.groups[0].independent_source_count == 2


def test_ml_prediction_and_shap_are_not_independent(engine):
    evidence = [
        EvidenceSource(
            source_id="ml-1",
            source_type="ml_prediction",
            scope="model_endpoint",
            detail="Model predicts elevated risk.",
            reference="POST /api/items",
            dependency_group="risk-model-v1",
        ),
        EvidenceSource(
            source_id="shap-1",
            source_type="shap",
            scope="model_endpoint",
            detail="SHAP explains the predicted class score.",
            reference="POST /api/items",
            dependency_group="risk-model-v1",
        ),
    ]

    result = engine.correlate(evidence)

    assert len(result.groups) == 1
    assert len(result.relationships) == 1
    assert result.relationships[0].relationship == "explains"
    assert result.relationships[0].independent_sources is False
    assert result.groups[0].independent_source_count == 1


def test_same_indicator_with_opposite_directions_conflicts(engine):
    evidence = [
        EvidenceSource(
            source_id="signal-positive",
            source_type="api_structure",
            scope="endpoint",
            detail="First observation.",
            reference="GET /api/items",
            indicator="authorization_signal",
            direction="positive",
        ),
        EvidenceSource(
            source_id="signal-negative",
            source_type="security_graph",
            scope="endpoint",
            detail="Second observation.",
            reference="GET /api/items",
            indicator="authorization_signal",
            direction="negative",
        ),
    ]

    result = engine.correlate(evidence)

    assert len(result.relationships) == 1
    assert result.relationships[0].relationship == "conflicts"


def test_same_indicator_with_same_direction_overlaps(engine):
    evidence = [
        EvidenceSource(
            source_id="signal-a",
            source_type="api_structure",
            scope="endpoint",
            detail="First observation.",
            reference="GET /api/items",
            indicator="object_identifier",
            direction="positive",
        ),
        EvidenceSource(
            source_id="signal-b",
            source_type="security_graph",
            scope="endpoint",
            detail="Second observation.",
            reference="GET /api/items",
            indicator="object_identifier",
            direction="positive",
        ),
    ]

    result = engine.correlate(evidence)

    assert len(result.relationships) == 1
    assert result.relationships[0].relationship == "overlaps"


def test_documented_catalog_match_is_distinguished(engine):
    evidence = [
        EvidenceSource(
            source_id="structure-1",
            source_type="api_structure",
            scope="endpoint",
            detail="Endpoint structure observed.",
            reference="DELETE /api/items/{item_id}",
        ),
        EvidenceSource(
            source_id="catalog-1",
            source_type="documented_catalog",
            scope="endpoint",
            detail="Matching documented reference.",
            reference="DELETE /api/items/{item_id}",
        ),
    ]

    result = engine.correlate(evidence)

    assert len(result.relationships) == 1
    assert result.relationships[0].relationship == "documented_match"


def test_assessment_graph_is_not_merged_with_endpoint_evidence(engine):
    evidence = [
        EvidenceSource(
            source_id="endpoint-1",
            source_type="api_structure",
            scope="endpoint",
            detail="Endpoint-specific evidence.",
            reference="GET /api/items/{item_id}",
        ),
        EvidenceSource(
            source_id="graph-1",
            source_type="security_graph",
            scope="assessment_graph",
            detail="Assessment-wide graph evidence.",
            reference="GET /api/items/{item_id}",
        ),
    ]

    result = engine.correlate(evidence)

    assert len(result.groups) == 2
    assert result.total_relationships == 0
    assert {group.scope for group in result.groups} == {
        "endpoint",
        "assessment_graph",
    }


def test_different_references_are_not_correlated(engine):
    evidence = [
        EvidenceSource(
            source_id="signal-a",
            source_type="api_structure",
            scope="endpoint",
            detail="Evidence for endpoint A.",
            reference="GET /api/items",
        ),
        EvidenceSource(
            source_id="signal-b",
            source_type="security_graph",
            scope="endpoint",
            detail="Evidence for endpoint B.",
            reference="GET /api/users",
        ),
    ]

    result = engine.correlate(evidence)

    assert len(result.groups) == 2
    assert result.total_relationships == 0


def test_duplicate_source_ids_are_rejected(engine):
    evidence = [
        EvidenceSource(
            source_id="duplicate",
            source_type="api_structure",
            scope="endpoint",
            detail="First signal.",
            reference="GET /api/items",
        ),
        EvidenceSource(
            source_id="duplicate",
            source_type="security_graph",
            scope="endpoint",
            detail="Second signal.",
            reference="GET /api/items",
        ),
    ]

    with pytest.raises(ValueError, match="must be unique"):
        engine.correlate(evidence)


def test_empty_input_returns_empty_result(engine):
    result = engine.correlate([])

    assert result.groups == []
    assert result.relationships == []
    assert result.total_evidence_sources == 0
    assert result.total_relationships == 0

def test_api_structure_and_graph_share_provenance(engine):
    evidence = [
        EvidenceSource(
            source_id="structure-1",
            source_type="api_structure",
            scope="endpoint",
            detail="Path identifier detected.",
            reference="GET /api/items/{item_id}",
            dependency_group="openapi-static-assessment",
        ),
        EvidenceSource(
            source_id="graph-1",
            source_type="security_graph",
            scope="endpoint",
            detail="Object operation detected.",
            reference="GET /api/items/{item_id}",
            dependency_group="openapi-static-assessment",
        ),
    ]

    result = engine.correlate(evidence)

    assert result.relationships[0].relationship == "overlaps"
    assert result.relationships[0].independent_sources is False
    assert result.groups[0].independent_source_count == 1


def test_documented_catalog_is_a_separate_dependency(engine):
    evidence = [
        EvidenceSource(
            source_id="structure-1",
            source_type="api_structure",
            scope="endpoint",
            detail="Endpoint structure.",
            reference="DELETE /api/items/{item_id}",
            dependency_group="openapi-static-assessment",
        ),
        EvidenceSource(
            source_id="catalog-1",
            source_type="documented_catalog",
            scope="endpoint",
            detail="Documented reference.",
            reference="DELETE /api/items/{item_id}",
            dependency_group="documented-security-catalog",
        ),
    ]

    result = engine.correlate(evidence)

    assert result.relationships[0].relationship == "documented_match"
    assert result.relationships[0].independent_sources is True
    assert result.groups[0].independent_source_count == 2
