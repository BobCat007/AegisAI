from __future__ import annotations

import math
from typing import Any, Iterable

from api_discovery.models import APIObjectOperationSurface
from ai.graph_intelligence.schema import GRAPH_FEATURE_NAMES


READ_METHODS = frozenset({"GET"})
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
DELETE_METHODS = frozenset({"DELETE"})
MUTATION_METHODS = WRITE_METHODS | DELETE_METHODS

ASSESSMENT_GRAPH_SCOPE = "assessment_graph"


class GraphExplanationMapper:
    """
    Maps aggregate graph-feature SHAP contributions to the API object
    surfaces that caused those graph features to be present.

    The evidence is assessment-level. It must not be interpreted as proof
    that a particular endpoint is vulnerable.
    """

    def map_feature(
        self,
        feature_name: str,
        feature_value: float,
        shap_value: float,
        surfaces: Iterable[APIObjectOperationSurface],
    ) -> dict[str, Any]:
        if feature_name not in GRAPH_FEATURE_NAMES:
            raise ValueError(
                f"Unsupported graph feature: {feature_name}"
            )

        value = float(feature_value)
        contribution = float(shap_value)

        if not math.isfinite(value):
            raise ValueError("feature_value must be finite")

        if not math.isfinite(contribution):
            raise ValueError("shap_value must be finite")

        matching_surfaces = [
            surface
            for surface in surfaces
            if self._matches_feature(feature_name, surface)
        ]

        evidence = [
            self._build_object_evidence(feature_name, surface)
            for surface in matching_surfaces
        ]

        matched_count = len(evidence)

        return {
            "feature_name": feature_name,
            "feature_value": value,
            "shap_value": contribution,
            "direction": self._get_direction(contribution),
            "scope": ASSESSMENT_GRAPH_SCOPE,
            "matched_object_count": matched_count,
            "count_matches": math.isclose(
                value,
                float(matched_count),
                rel_tol=0.0,
                abs_tol=1e-6,
            ),
            "evidence": evidence,
        }

    def map_contributions(
        self,
        contributions: Iterable[Any],
        surfaces: Iterable[APIObjectOperationSurface],
    ) -> list[dict[str, Any]]:
        """
        Maps graph-related SHAP contributions only.

        Each contribution is expected to expose:
        feature_name, feature_value and shap_value attributes.
        """

        surface_list = list(surfaces)
        mapped: list[dict[str, Any]] = []

        for contribution in contributions:
            feature_name = contribution.feature_name

            if feature_name not in GRAPH_FEATURE_NAMES:
                continue

            mapped.append(
                self.map_feature(
                    feature_name=feature_name,
                    feature_value=contribution.feature_value,
                    shap_value=contribution.shap_value,
                    surfaces=surface_list,
                )
            )

        return mapped

    @staticmethod
    def _get_methods(
        surface: APIObjectOperationSurface,
    ) -> frozenset[str]:
        return frozenset(
            str(method).upper()
            for method in surface.operations
        )

    def _matches_feature(
        self,
        feature_name: str,
        surface: APIObjectOperationSurface,
    ) -> bool:
        methods = self._get_methods(surface)

        has_read = bool(methods & READ_METHODS)
        has_write = bool(methods & WRITE_METHODS)
        has_delete = bool(methods & DELETE_METHODS)
        has_mutation = bool(methods & MUTATION_METHODS)
        has_multiple_mutations = (
            len(methods & MUTATION_METHODS) > 1
        )

        if feature_name == "objects_with_full_operation_surface":
            return has_read and has_write and has_delete

        if feature_name == "objects_with_mutation_without_read":
            return not has_read and has_mutation

        if feature_name == "objects_with_delete_without_read":
            return not has_read and has_delete

        if feature_name == "objects_with_write_without_read":
            return not has_read and has_write

        if feature_name == "objects_with_multiple_mutation_types":
            return has_multiple_mutations

        if feature_name == "objects_with_write_and_delete_without_read":
            return not has_read and has_write and has_delete

        raise ValueError(
            f"Unsupported graph feature: {feature_name}"
        )

    def _build_object_evidence(
        self,
        feature_name: str,
        surface: APIObjectOperationSurface,
    ) -> dict[str, Any]:
        methods = sorted(self._get_methods(surface))

        reasons = {
            "objects_with_full_operation_surface": (
                "The object has a read operation, at least one write "
                "operation, and a delete operation."
            ),
            "objects_with_mutation_without_read": (
                "The object has a mutation operation but no GET operation."
            ),
            "objects_with_delete_without_read": (
                "The object has a DELETE operation but no GET operation."
            ),
            "objects_with_write_without_read": (
                "The object has a write operation but no GET operation."
            ),
            "objects_with_multiple_mutation_types": (
                "The object supports more than one distinct mutation method."
            ),
            "objects_with_write_and_delete_without_read": (
                "The object has both write and DELETE operations "
                "but no GET operation."
            ),
        }

        return {
            "path_template": surface.path_template,
            "object_identifier_names": list(
                surface.object_identifier_names
            ),
            "operations": methods,
            "reason": reasons[feature_name],
        }

    @staticmethod
    def _get_direction(shap_value: float) -> str:
        if shap_value > 0:
            return "increases_class_score"

        if shap_value < 0:
            return "decreases_class_score"

        return "no_effect"
