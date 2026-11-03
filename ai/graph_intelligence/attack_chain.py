from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from ai.graph_intelligence.relationships import (
    ResourceRelationship,
    ResourceRelationshipGraph,
)


class AttackChain(BaseModel):
    """A bounded, structurally inferred API resource path."""

    resources: list[str]
    relationships: list[ResourceRelationship]
    hop_count: int = Field(ge=1)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_sources: list[str] = Field(default_factory=list)
    interpretation: str = (
        "Inferred structural path; not a confirmed exploit."
    )


class AttackChainResult(BaseModel):
    """Collection of reconstructed structural paths."""

    chains: list[AttackChain] = Field(default_factory=list)
    total_chains_found: int = 0
    truncated: bool = False


class AttackChainBuilder:
    """Reconstruct bounded simple paths from resource relationships."""

    def __init__(
        self,
        max_hops: int = 5,
        max_chains: int = 100,
        min_confidence: float = 0.0,
    ) -> None:
        if max_hops < 1:
            raise ValueError("max_hops must be at least 1.")

        if max_chains < 1:
            raise ValueError("max_chains must be at least 1.")

        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1.")

        self.max_hops = max_hops
        self.max_chains = max_chains
        self.min_confidence = min_confidence

    def build(
        self,
        graph: ResourceRelationshipGraph,
    ) -> AttackChainResult:
        """Build bounded paths from a relationship graph."""

        adjacency: dict[str, list[ResourceRelationship]] = defaultdict(list)

        for relationship in graph.relationships:
            if relationship.confidence >= self.min_confidence:
                adjacency[relationship.source_resource].append(
                    relationship
                )

        for edges in adjacency.values():
            edges.sort(
                key=lambda edge: (
                    edge.target_resource,
                    edge.relationship_type,
                    edge.evidence,
                    edge.evidence_source,
                )
            )

        chains: list[AttackChain] = []
        seen: set[tuple[str, ...]] = set()
        truncated = False

        def visit(
            current: str,
            resources: list[str],
            relationships: list[ResourceRelationship],
        ) -> None:
            nonlocal truncated

            if truncated or len(relationships) >= self.max_hops:
                return

            for edge in adjacency.get(current, []):
                target = edge.target_resource

                if target in resources:
                    continue

                next_resources = resources + [target]
                next_relationships = relationships + [edge]
                path_key = tuple(next_resources)

                if path_key not in seen:
                    # Only report truncation when an additional unique
                    # path actually exists beyond the configured limit.
                    if len(chains) >= self.max_chains:
                        truncated = True
                        return

                    seen.add(path_key)

                    confidence = sum(
                        item.confidence for item in next_relationships
                    ) / len(next_relationships)

                    evidence_sources = sorted({
                        item.evidence_source
                        for item in next_relationships
                    })

                    chains.append(
                        AttackChain(
                            resources=next_resources,
                            relationships=next_relationships,
                            hop_count=len(next_relationships),
                            confidence=confidence,
                            evidence_sources=evidence_sources,
                        )
                    )

                visit(
                    target,
                    next_resources,
                    next_relationships,
                )

                if truncated:
                    return

        for start in sorted(adjacency.keys()):
            visit(start, [start], [])

            if truncated:
                break

        return AttackChainResult(
            chains=chains,
            total_chains_found=len(chains),
            truncated=truncated,
        )


def build_attack_chains(
    graph: ResourceRelationshipGraph,
    max_hops: int = 5,
    max_chains: int = 100,
    min_confidence: float = 0.0,
) -> AttackChainResult:
    """Convenience function for structural path reconstruction."""

    return AttackChainBuilder(
        max_hops=max_hops,
        max_chains=max_chains,
        min_confidence=min_confidence,
    ).build(graph)
