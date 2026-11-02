from collections import defaultdict

from ai.security_reasoning.models import (
    EvidenceAssessmentResult,
    EvidenceCorrelationResult,
    EvidenceSourceAssessment,
    EvidenceStrengthAssessment,
    EvidenceValidationAssessment,
    RiskPrioritizationAssessment,
)


class EvidenceConfidenceEngine:
    """
    Assess evidence strength and endpoint prioritization.

    Reliability weights are engineering heuristics, not probabilities.
    Signals sharing a dependency group are counted only once.
    """

    SOURCE_RELIABILITY = {
        "api_structure": 0.55,
        "security_graph": 0.60,
        "ml_prediction": 0.35,
        "shap": 0.20,
        "documented_catalog": 0.75,
        "runtime_validation": 0.95,
    }

    CONFLICT_PENALTY = 15
    MAX_CONFLICT_PENALTY = 30
    MAX_PRIORITY_BOOST = 0.20

    def assess(
        self,
        correlation: EvidenceCorrelationResult,
        baseline_score: float,
        baseline_severity: str,
    ) -> EvidenceAssessmentResult:
        if not 0 <= baseline_score <= 100:
            raise ValueError("baseline_score must be between 0 and 100")

        sources = [
            source
            for group in correlation.groups
            for source in group.evidence
            if source.scope != "assessment_graph"
        ]

        grouped_sources = defaultdict(list)

        for source in sources:
            dependency = (
                source.dependency_group
                or f"independent:{source.source_id}"
            )
            grouped_sources[dependency].append(source)

        source_assessments = []
        combined_reliability = 1.0

        for dependency, dependency_sources in sorted(
            grouped_sources.items()
        ):
            reliability = max(
                self.SOURCE_RELIABILITY[source.source_type]
                for source in dependency_sources
            )

            combined_reliability *= 1.0 - reliability

            source_assessments.append(
                EvidenceSourceAssessment(
                    dependency_group=dependency,
                    source_types=sorted(
                        {
                            source.source_type
                            for source in dependency_sources
                        }
                    ),
                    reliability_weight=reliability,
                    evidence_count=len(dependency_sources),
                    independent=True,
                )
            )

        raw_score = 1.0 - combined_reliability

        # Count distinct conflicting source pairs only.
        conflicting_pairs = {
            tuple(
                sorted(
                    (
                        relationship.source_id_a,
                        relationship.source_id_b,
                    )
                )
            )
            for relationship in correlation.relationships
            if relationship.relationship == "conflicts"
        }

        conflict_count = len(conflicting_pairs)
        conflict_penalty = min(
            conflict_count * self.CONFLICT_PENALTY,
            self.MAX_CONFLICT_PENALTY,
        )

        evidence_score = max(
            0,
            min(100, round(raw_score * 100) - conflict_penalty),
        )

        if evidence_score >= 70:
            evidence_level = "high"
        elif evidence_score >= 40:
            evidence_level = "medium"
        else:
            evidence_level = "low"

        rationale = [
            (
                f"{len(source_assessments)} independent dependency "
                "group(s) contributed to the assessment."
            ),
            (
                "Signals from the same dependency group use only "
                "the highest reliability weight."
            ),
        ]

        if conflict_count:
            rationale.append(
                f"{conflict_count} conflicting evidence relationship(s) "
                f"reduced the score by {conflict_penalty} points."
            )

        if not sources:
            rationale.append(
                "No endpoint-scoped evidence sources were available."
            )

        strength = EvidenceStrengthAssessment(
            score=evidence_score,
            level=evidence_level,
            independent_source_count=len(source_assessments),
            source_assessments=source_assessments,
            conflict_count=conflict_count,
            conflict_penalty=conflict_penalty,
            rationale=rationale,
            limitations=[
                "Reliability weights are heuristic engineering values.",
                "Evidence strength is not the probability of a vulnerability.",
                "Multiple signals from one dependency group are not independent.",
                "Assessment-wide graph evidence is excluded from endpoint scoring.",
                "Synthetic ML predictions are experimental evidence only.",
            ],
        )

        runtime_validated = any(
            source.source_type == "runtime_validation"
            for source in sources
        )

        documented_reference = any(
            source.source_type == "documented_catalog"
            for source in sources
        )

        if runtime_validated:
            validation_status = "runtime_validated"
            validation_explanation = (
                "Runtime validation evidence is present. Review its "
                "underlying test results before treating a vulnerability "
                "as confirmed."
            )
        elif documented_reference:
            validation_status = "documented_reference"
            validation_explanation = (
                "A documented security reference is present, but the "
                "target endpoint has not been runtime validated."
            )
        else:
            validation_status = "not_validated"
            validation_explanation = (
                "Only structural, graph, or model-derived signals are "
                "available. No runtime validation evidence is present."
            )

        validation = EvidenceValidationAssessment(
            status=validation_status,
            runtime_validated=runtime_validated,
            documented_reference_present=documented_reference,
            explanation=validation_explanation,
        )

        # Evidence can increase priority by at most 20% of the
        # remaining distance to 100. It never reduces baseline risk.
        adjustment = (
            (100.0 - baseline_score)
            * self.MAX_PRIORITY_BOOST
            * (evidence_score / 100.0)
        )

        priority_score = min(
            100,
            round(baseline_score + adjustment),
        )

        if priority_score >= 80:
            priority_level = "critical"
        elif priority_score >= 60:
            priority_level = "high"
        elif priority_score >= 30:
            priority_level = "medium"
        else:
            priority_level = "low"

        prioritization = RiskPrioritizationAssessment(
            baseline_score=baseline_score,
            baseline_severity=baseline_severity,
            evidence_strength_score=evidence_score,
            priority_score=priority_score,
            priority_level=priority_level,
            adjustment=round(priority_score - baseline_score, 2),
            rationale=(
                "Baseline risk remains unchanged. Evidence strength "
                "provides a bounded upward prioritization adjustment "
                "of at most 20% of the remaining score range."
            ),
            scoring_method=(
                "priority = min(100, round(baseline + "
                "(100 - baseline) * 0.20 * evidence_strength / 100))"
            ),
            vulnerabilities_confirmed=False,
        )

        return EvidenceAssessmentResult(
            evidence_strength=strength,
            validation_status=validation,
            risk_prioritization=prioritization,
            vulnerabilities_confirmed=False,
        )
