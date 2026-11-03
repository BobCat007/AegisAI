import pytest

from ai.graph_intelligence.attack_chain import (
    AttackChainBuilder,
    build_attack_chains,
)
from ai.graph_intelligence.attack_chain_ranker import (
    AttackChainRanker,
    rank_attack_chains,
)
from ai.graph_intelligence.relationships import (
    ResourceRelationship,
    ResourceRelationshipGraph,
)


def make_relationship(
    source,
    target,
    confidence=0.9,
    evidence_source="schema_reference",
):
    return ResourceRelationship(
        source_resource=source,
        target_resource=target,
        relationship_type="schema_reference",
        evidence_source=evidence_source,
        evidence=f"{source}.{target}",
        confidence=confidence,
    )


def make_graph(relationships):
    return ResourceRelationshipGraph(
        relationships=relationships
    )


def test_builds_linear_attack_chain():
    graph = make_graph([
        make_relationship("user", "order"),
        make_relationship("order", "payment"),
    ])

    result = build_attack_chains(graph)

    assert any(
        chain.resources == ["user", "order", "payment"]
        for chain in result.chains
    )


def test_builds_multiple_paths():
    graph = make_graph([
        make_relationship("user", "order"),
        make_relationship("user", "profile"),
    ])

    result = build_attack_chains(graph)

    paths = [chain.resources for chain in result.chains]

    assert ["user", "order"] in paths
    assert ["user", "profile"] in paths


def test_respects_maximum_hops():
    graph = make_graph([
        make_relationship("a", "b"),
        make_relationship("b", "c"),
        make_relationship("c", "d"),
    ])

    result = build_attack_chains(graph, max_hops=2)

    assert all(chain.hop_count <= 2 for chain in result.chains)


def test_prevents_cycles():
    graph = make_graph([
        make_relationship("a", "b"),
        make_relationship("b", "c"),
        make_relationship("c", "a"),
    ])

    result = build_attack_chains(graph)

    assert all(
        len(chain.resources) == len(set(chain.resources))
        for chain in result.chains
    )


def test_respects_minimum_confidence():
    graph = make_graph([
        make_relationship("user", "order", confidence=0.4),
        make_relationship("order", "payment", confidence=0.9),
    ])

    result = build_attack_chains(
        graph,
        min_confidence=0.7,
    )

    assert all(
        relationship.confidence >= 0.7
        for chain in result.chains
        for relationship in chain.relationships
    )


def test_respects_maximum_chain_count():
    graph = make_graph([
        make_relationship("a", "b"),
        make_relationship("a", "c"),
        make_relationship("a", "d"),
    ])

    result = build_attack_chains(
        graph,
        max_chains=2,
    )

    assert len(result.chains) == 2
    assert result.truncated is True


def test_records_evidence_sources():
    graph = make_graph([
        make_relationship(
            "user",
            "order",
            evidence_source="path",
        ),
        make_relationship(
            "order",
            "payment",
            evidence_source="schema_reference",
        ),
    ])

    result = build_attack_chains(graph)

    chain = next(
        chain for chain in result.chains
        if chain.resources == ["user", "order", "payment"]
    )

    assert chain.evidence_sources == ["path", "schema_reference"]


def test_empty_graph_returns_no_chains():
    result = build_attack_chains(
        ResourceRelationshipGraph()
    )

    assert result.chains == []
    assert result.total_chains_found == 0
    assert result.truncated is False


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        AttackChainBuilder(max_hops=0)

    with pytest.raises(ValueError):
        AttackChainBuilder(max_chains=0)

    with pytest.raises(ValueError):
        AttackChainBuilder(min_confidence=1.5)


def test_ranker_prioritizes_higher_confidence():
    graph = make_graph([
        make_relationship("a", "b", confidence=0.5),
        make_relationship("x", "y", confidence=0.95),
    ])

    result = build_attack_chains(graph)
    ranked = rank_attack_chains(result)

    assert ranked.chains[0].resources == ["x", "y"]


def test_ranker_applies_path_length_penalty():
    graph = make_graph([
        make_relationship("a", "b", confidence=0.9),
        make_relationship("x", "y", confidence=0.9),
        make_relationship("y", "z", confidence=0.9),
    ])

    result = build_attack_chains(graph)

    short_chain = next(
        chain for chain in result.chains
        if chain.resources == ["a", "b"]
    )

    long_chain = next(
        chain for chain in result.chains
        if chain.resources == ["x", "y", "z"]
    )

    ranker = AttackChainRanker()

    assert long_chain.hop_count == 2
    assert short_chain.hop_count == 1
    assert ranker.score(short_chain) > ranker.score(long_chain)


def test_ranker_is_deterministic():
    graph = make_graph([
        make_relationship("a", "c"),
        make_relationship("a", "b"),
        make_relationship("b", "d"),
    ])

    first = rank_attack_chains(build_attack_chains(graph))
    second = rank_attack_chains(build_attack_chains(graph))

    assert [
        chain.resources for chain in first.chains
    ] == [
        chain.resources for chain in second.chains
    ]


def test_ranker_preserves_truncation_metadata():
    graph = make_graph([
        make_relationship("a", "b"),
        make_relationship("a", "c"),
        make_relationship("a", "d"),
    ])

    original = build_attack_chains(graph, max_chains=2)
    ranked = rank_attack_chains(original)

    assert ranked.truncated is True
    assert ranked.total_chains_found == original.total_chains_found


def test_ranker_score_is_bounded():
    graph = make_graph([
        make_relationship("a", "b", confidence=0.8),
        make_relationship("b", "c", confidence=1.0),
    ])

    result = build_attack_chains(graph)
    ranker = AttackChainRanker()

    assert all(
        0.0 <= ranker.score(chain) <= 1.0
        for chain in result.chains
    )


def test_exact_chain_limit_does_not_report_false_truncation():
    graph = make_graph([
        make_relationship("a", "b"),
        make_relationship("a", "c"),
    ])

    result = build_attack_chains(graph, max_chains=2)

    assert len(result.chains) == 2
    assert result.total_chains_found == 2
    assert result.truncated is False


def test_chain_limit_reports_truncation_only_when_extra_path_exists():
    graph = make_graph([
        make_relationship("a", "b"),
        make_relationship("a", "c"),
        make_relationship("a", "d"),
    ])

    result = build_attack_chains(graph, max_chains=2)

    assert len(result.chains) == 2
    assert result.total_chains_found == 2
    assert result.truncated is True
