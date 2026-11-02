from collections import defaultdict

from ai.security_reasoning.models import (
    CorrelatedEvidenceGroup,
    EvidenceCorrelationResult,
    EvidenceRelationship,
    EvidenceSource,
    SecurityReasoningResult,
)


class EvidenceCorrelationEngine:
    """
    Correlate normalized security evidence without treating correlation
    as proof or automatically increasing confidence.

    Evidence is grouped only when both scope and reference match.
    Dependency groups represent shared provenance.
    """

    @staticmethod
    def _is_independent(
        evidence_a: EvidenceSource,
        evidence_b: EvidenceSource,
    ) -> bool:
        if (
            evidence_a.dependency_group
            and evidence_b.dependency_group
            and evidence_a.dependency_group == evidence_b.dependency_group
        ):
            return False

        return True

    @staticmethod
    def _relationship_for(
        evidence_a: EvidenceSource,
        evidence_b: EvidenceSource,
    ) -> tuple[str, str, bool]:
        independent = EvidenceCorrelationEngine._is_independent(
            evidence_a,
            evidence_b,
        )

        source_types = {
            evidence_a.source_type,
            evidence_b.source_type,
        }

        if "documented_catalog" in source_types:
            return (
                "documented_match",
                (
                    "One signal comes from the documented evidence catalog "
                    "and shares the same evidence scope and reference. "
                    "This is a catalog match, not runtime confirmation."
                ),
                independent,
            )

        if not independent:
            if source_types == {"ml_prediction", "shap"}:
                return (
                    "explains",
                    (
                        "The ML prediction and SHAP explanation share the "
                        "same model dependency. SHAP explains model output "
                        "and is not independent confirmation."
                    ),
                    False,
                )

            return (
                "overlaps",
                (
                    "These signals share provenance and may describe "
                    "overlapping observations. They must not be counted "
                    "as independent evidence."
                ),
                False,
            )

        same_indicator = (
            evidence_a.indicator is not None
            and evidence_a.indicator == evidence_b.indicator
        )

        opposite_directions = (
            evidence_a.direction is not None
            and evidence_b.direction is not None
            and evidence_a.direction != "neutral"
            and evidence_b.direction != "neutral"
            and evidence_a.direction != evidence_b.direction
        )

        if same_indicator and opposite_directions:
            return (
                "conflicts",
                (
                    "The signals refer to the same indicator but describe "
                    "opposite directions."
                ),
                True,
            )

        if same_indicator:
            return (
                "overlaps",
                (
                    "The signals refer to the same indicator and may "
                    "describe overlapping evidence."
                ),
                True,
            )

        return (
            "supports",
            (
                "The signals come from different independent source groups "
                "and concern the same scope and reference."
            ),
            True,
        )

    @staticmethod
    def _finding_source_type(finding) -> str:
        if finding.category == "documented_vulnerability_reference":
            return "documented_catalog"

        if finding.category in {
            "mutation_without_read_review",
            "delete_without_read_review",
            "multiple_mutation_types_review",
        }:
            return "security_graph"

        if finding.category in {
            "shap_dominant_feature",
            "shap_risk_increasing_feature",
            "shap_risk_decreasing_feature",
        }:
            return "shap"

        return "api_structure"

    @staticmethod
    def _finding_indicator(finding) -> str:
        indicators = {
            "bola_review": "object_authorization_review",
            "bfla_review": "destructive_operation_review",
            "destructive_operation_review": "destructive_operation_review",
            "sensitive_data_review": "sensitive_response_data_review",
            "mutation_without_read_review": "mutation_without_read",
            "delete_without_read_review": "mutation_without_read",
            "multiple_mutation_types_review": "multiple_mutation_types",
            "documented_vulnerability_reference": "documented_reference",
        }

        if finding.category.startswith("shap_"):
            for item in finding.evidence:
                if item.source == "SHAP model explanation":
                    feature_name = item.detail.split("'")
                    if len(feature_name) >= 2:
                        return f"shap_feature:{feature_name[1]}"

            return "shap_model_contribution"

        return indicators.get(
            finding.category,
            finding.category,
        )

    @staticmethod
    def _finding_direction(finding) -> str:
        if finding.category == "shap_risk_increasing_feature":
            return "positive"

        if finding.category == "shap_risk_decreasing_feature":
            return "negative"

        return "neutral"

    @staticmethod
    def _dependency_group(source_type: str) -> str:
        if source_type in {"api_structure", "security_graph"}:
            return "openapi-static-assessment"

        if source_type in {"ml_prediction", "shap"}:
            return "xgboost-risk-model"

        if source_type == "documented_catalog":
            return "documented-security-catalog"

        return source_type

    def normalize_endpoint(
        self,
        reasoning: SecurityReasoningResult,
        predicted_label: str | None = None,
        ml_prediction_available: bool = False,
    ) -> list[EvidenceSource]:
        """
        Convert endpoint reasoning findings and an optional ML prediction
        into normalized evidence signals.
        """

        endpoint_reference = (
            f"{reasoning.method.upper()} {reasoning.path}"
        )

        normalized: list[EvidenceSource] = []

        for index, finding in enumerate(reasoning.findings):
            source_type = self._finding_source_type(finding)

            scope = (
                "model_endpoint"
                if source_type == "shap"
                else "endpoint"
            )

            normalized.append(
                EvidenceSource(
                    source_id=f"finding:{finding.finding_id}:{index}",
                    source_type=source_type,
                    scope=scope,
                    detail=f"{finding.title}: {finding.explanation}",
                    reference=endpoint_reference,
                    indicator=self._finding_indicator(finding),
                    direction=self._finding_direction(finding),
                    dependency_group=self._dependency_group(source_type),
                )
            )

        if ml_prediction_available and predicted_label is not None:
            normalized.append(
                EvidenceSource(
                    source_id="ml-prediction",
                    source_type="ml_prediction",
                    scope="model_endpoint",
                    detail=(
                        "The XGBoost model predicted risk class "
                        f"'{predicted_label}'. This is an experimental "
                        "model output, not a verified security finding."
                    ),
                    reference=endpoint_reference,
                    indicator="predicted_risk_class",
                    direction="neutral",
                    dependency_group="xgboost-risk-model",
                )
            )

        return normalized

    def correlate(
        self,
        evidence_sources: list[EvidenceSource],
    ) -> EvidenceCorrelationResult:
        """
        Group evidence by scope and reference, then identify pairwise
        relationships inside each group.

        Duplicate source IDs are rejected to keep relationships traceable.
        """

        source_ids = [item.source_id for item in evidence_sources]

        if len(source_ids) != len(set(source_ids)):
            raise ValueError("Evidence source IDs must be unique.")

        grouped_sources: dict[
            tuple[str, str | None],
            list[EvidenceSource],
        ] = defaultdict(list)

        for evidence in evidence_sources:
            grouped_sources[
                (evidence.scope, evidence.reference)
            ].append(evidence)

        groups: list[CorrelatedEvidenceGroup] = []
        all_relationships: list[EvidenceRelationship] = []

        for group_index, ((scope, reference), items) in enumerate(
            sorted(
                grouped_sources.items(),
                key=lambda entry: (
                    entry[0][0],
                    entry[0][1] or "",
                ),
            ),
            start=1,
        ):
            group_relationships: list[EvidenceRelationship] = []

            for index, evidence_a in enumerate(items):
                for evidence_b in items[index + 1:]:
                    relationship_type, rationale, independent = (
                        self._relationship_for(evidence_a, evidence_b)
                    )

                    relationship = EvidenceRelationship(
                        source_id_a=evidence_a.source_id,
                        source_id_b=evidence_b.source_id,
                        relationship=relationship_type,
                        rationale=rationale,
                        independent_sources=independent,
                    )

                    group_relationships.append(relationship)
                    all_relationships.append(relationship)

            independent_groups = {
                item.dependency_group or f"source:{item.source_id}"
                for item in items
            }

            groups.append(
                CorrelatedEvidenceGroup(
                    group_id=f"CORRELATED-GROUP-{group_index}",
                    scope=scope,
                    reference=reference,
                    evidence=items,
                    relationships=group_relationships,
                    independent_source_count=len(independent_groups),
                )
            )

        return EvidenceCorrelationResult(
            groups=groups,
            relationships=all_relationships,
            total_evidence_sources=len(evidence_sources),
            total_relationships=len(all_relationships),
        )
