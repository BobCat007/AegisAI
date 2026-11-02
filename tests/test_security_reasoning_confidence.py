from ai.security_reasoning.confidence import EvidenceConfidenceEngine
from ai.security_reasoning.models import (
    EvidenceCorrelationResult,
    EvidenceRelationship,
    EvidenceSource,
    CorrelatedEvidenceGroup,
)


def make_source(
    source_id,
    source_type,
    dependency_group,
    scope="endpoint",
):
    return EvidenceSource(
        source_id=source_id,
        source_type=source_type,
        scope=scope,
        detail=f"Test evidence: {source_type}",
        reference="GET /api/items/{id}",
        dependency_group=dependency_group,
    )


def make_correlation(sources, relationships=None):
    group = CorrelatedEvidenceGroup(
        group_id="test-group",
        scope="endpoint",
        reference="GET /api/items/{id}",
        evidence=sources,
        relationships=relationships or [],
        independent_source_count=len(
            {
                source.dependency_group or source.source_id
                for source in sources
            }
        ),
    )

    return EvidenceCorrelationResult(
        groups=[group],
        relationships=relationships or [],
        total_evidence_sources=len(sources),
        total_relationships=len(relationships or []),
    )


def test_empty_evidence_has_zero_strength():
    engine = EvidenceConfidenceEngine()

    result = engine.assess(
        EvidenceCorrelationResult(),
        baseline_score=40,
        baseline_severity="medium",
    )

    assert result.evidence_strength.score == 0
    assert result.evidence_strength.level == "low"
    assert result.evidence_strength.independent_source_count == 0
    assert result.validation_status.status == "not_validated"


def test_same_dependency_group_is_not_double_counted():
    engine = EvidenceConfidenceEngine()

    correlation = make_correlation(
        [
            make_source("api", "api_structure", "static"),
            make_source("graph", "security_graph", "static"),
        ]
    )

    result = engine.assess(correlation, 50, "medium")

    assert result.evidence_strength.independent_source_count == 1
    assert result.evidence_strength.score == 60
    assert result.evidence_strength.source_assessments[0].reliability_weight == 0.60


def test_independent_sources_combine():
    engine = EvidenceConfidenceEngine()

    correlation = make_correlation(
        [
            make_source("static", "security_graph", "static"),
            make_source("catalog", "documented_catalog", "catalog"),
        ]
    )

    result = engine.assess(correlation, 50, "medium")

    assert result.evidence_strength.independent_source_count == 2
    assert result.evidence_strength.score == 90
    assert result.validation_status.status == "documented_reference"


def test_conflicting_evidence_reduces_strength():
    engine = EvidenceConfidenceEngine()

    sources = [
        make_source("static", "security_graph", "static"),
        make_source("catalog", "documented_catalog", "catalog"),
    ]

    relationship = EvidenceRelationship(
        source_id_a="static",
        source_id_b="catalog",
        relationship="conflicts",
        rationale="Test conflict",
        independent_sources=True,
    )

    correlation = make_correlation(
        sources,
        [relationship],
    )

    result = engine.assess(correlation, 50, "medium")

    assert result.evidence_strength.conflict_count == 1
    assert result.evidence_strength.conflict_penalty == 15
    assert result.evidence_strength.score == 75


def test_runtime_validation_is_distinguished():
    engine = EvidenceConfidenceEngine()

    correlation = make_correlation(
        [
            make_source(
                "runtime",
                "runtime_validation",
                "runtime-test",
            )
        ]
    )

    result = engine.assess(correlation, 50, "medium")

    assert result.validation_status.status == "runtime_validated"
    assert result.validation_status.runtime_validated is True


def test_priority_never_reduces_baseline_score():
    engine = EvidenceConfidenceEngine()

    correlation = make_correlation(
        [
            make_source("static", "security_graph", "static"),
        ]
    )

    result = engine.assess(correlation, 65, "high")

    assert result.risk_prioritization.priority_score >= 65
    assert result.risk_prioritization.baseline_score == 65


def test_priority_adjustment_is_bounded():
    engine = EvidenceConfidenceEngine()

    correlation = make_correlation(
        [
            make_source("runtime", "runtime_validation", "runtime"),
            make_source("catalog", "documented_catalog", "catalog"),
        ]
    )

    result = engine.assess(correlation, 50, "medium")

    assert result.risk_prioritization.priority_score <= 60


def test_assessment_never_confirms_vulnerabilities():
    engine = EvidenceConfidenceEngine()

    correlation = make_correlation(
        [
            make_source("runtime", "runtime_validation", "runtime"),
        ]
    )

    result = engine.assess(correlation, 80, "critical")

    assert result.vulnerabilities_confirmed is False
    assert result.risk_prioritization.vulnerabilities_confirmed is False
