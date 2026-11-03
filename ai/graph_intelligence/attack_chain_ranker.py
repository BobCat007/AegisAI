from __future__ import annotations

from ai.graph_intelligence.attack_chain import (
    AttackChain,
    AttackChainResult,
)


class AttackChainRanker:
    """
    Rank inferred structural paths using relationship confidence.

    The score is a prioritization heuristic, not an exploit probability.
    """

    @staticmethod
    def score(chain: AttackChain) -> float:
        if not chain.relationships:
            return 0.0

        confidence = sum(
            relationship.confidence
            for relationship in chain.relationships
        ) / len(chain.relationships)

        # Longer paths receive a modest complexity penalty.
        length_factor = 1.0 / (1.0 + 0.1 * (chain.hop_count - 1))

        return round(confidence * length_factor, 6)

    def rank(
        self,
        result: AttackChainResult,
    ) -> AttackChainResult:
        """Return chains sorted by heuristic score."""

        ranked = sorted(
            result.chains,
            key=lambda chain: (
                -self.score(chain),
                chain.hop_count,
                tuple(chain.resources),
            ),
        )

        return AttackChainResult(
            chains=ranked,
            total_chains_found=result.total_chains_found,
            truncated=result.truncated,
        )


def rank_attack_chains(
    result: AttackChainResult,
) -> AttackChainResult:
    """Convenience function for ranking structural paths."""

    return AttackChainRanker().rank(result)
