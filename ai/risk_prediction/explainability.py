from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import shap

from ai.risk_prediction.xgboost_model import XGBoostRiskPredictionModel
from ai.security_context_schema import (
    SECURITY_CONTEXT_FEATURE_COUNT,
    SECURITY_CONTEXT_FEATURE_NAMES,
)


@dataclass(frozen=True)
class FeatureContribution:
    """SHAP contribution of one feature to one risk class."""

    feature_name: str
    feature_value: float
    shap_value: float


@dataclass(frozen=True)
class ClassExplanation:
    """Explanation of one model output class."""

    risk_class: str
    base_value: float
    raw_model_output: float
    contributions: tuple[FeatureContribution, ...]


@dataclass(frozen=True)
class EndpointExplanation:
    """SHAP explanation for an individual endpoint sample."""

    predicted_label: str
    probabilities: dict[str, float]
    class_explanations: tuple[ClassExplanation, ...]


class RiskPredictionExplainer:
    """
    Explain XGBoost risk predictions using SHAP TreeExplainer.

    SHAP values explain the model's raw class scores. They do not
    independently establish that an endpoint is vulnerable.
    """

    def __init__(
        self,
        model: XGBoostRiskPredictionModel,
    ) -> None:
        if not model._is_fitted:
            raise RuntimeError(
                "Cannot initialize explainability for an unfitted model."
            )

        if model.model.n_features_in_ != SECURITY_CONTEXT_FEATURE_COUNT:
            raise ValueError(
                "Model feature schema mismatch: "
                f"expected {SECURITY_CONTEXT_FEATURE_COUNT}, "
                f"found {model.model.n_features_in_}."
            )

        self.model = model
        self.explainer = shap.TreeExplainer(model.model)

    @classmethod
    def from_model_file(
        cls,
        path: str | Path,
    ) -> "RiskPredictionExplainer":
        """Load a trained model artifact and initialize SHAP."""

        model = XGBoostRiskPredictionModel.load(path)
        return cls(model)

    def explain(
        self,
        features: list[list[float]],
    ) -> list[EndpointExplanation]:
        """
        Generate class-specific SHAP explanations.

        Returns one explanation per supplied feature vector.
        """

        self.model._validate_for_prediction(features)

        feature_array = np.asarray(features, dtype=np.float64)

        shap_values = self.explainer.shap_values(feature_array)

        raw_outputs = self.model.model.predict(
            feature_array,
            output_margin=True,
        )

        probabilities = self.model.predict_proba(features)
        predictions = self.model.predict(features)

        normalized_values = self._normalize_shap_values(
            shap_values,
            sample_count=len(features),
        )

        base_values = self._normalize_base_values(
            self.explainer.expected_value,
        )

        explanations: list[EndpointExplanation] = []

        for sample_index, feature_vector in enumerate(features):
            class_explanations: list[ClassExplanation] = []

            for class_index, risk_class in enumerate(
                self.model.INDEX_TO_LABEL.values()
            ):
                contributions = tuple(
                    FeatureContribution(
                        feature_name=feature_name,
                        feature_value=float(feature_vector[feature_index]),
                        shap_value=float(
                            normalized_values[
                                sample_index,
                                feature_index,
                                class_index,
                            ]
                        ),
                    )
                    for feature_index, feature_name in enumerate(
                        SECURITY_CONTEXT_FEATURE_NAMES
                    )
                )

                class_explanations.append(
                    ClassExplanation(
                        risk_class=risk_class,
                        base_value=float(base_values[class_index]),
                        raw_model_output=float(
                            raw_outputs[sample_index, class_index]
                        ),
                        contributions=contributions,
                    )
                )

            explanations.append(
                EndpointExplanation(
                    predicted_label=predictions[sample_index],
                    probabilities=probabilities[sample_index],
                    class_explanations=tuple(class_explanations),
                )
            )

        return explanations

    def global_feature_importance(
        self,
        features: list[list[float]],
    ) -> list[dict[str, Any]]:
        """
        Calculate mean absolute SHAP importance across samples and classes.

        Results are sorted from most influential to least influential.
        """

        self.model._validate_for_prediction(features)

        feature_array = np.asarray(features, dtype=np.float64)
        shap_values = self.explainer.shap_values(feature_array)

        normalized_values = self._normalize_shap_values(
            shap_values,
            sample_count=len(features),
        )

        mean_absolute_values = np.mean(
            np.abs(normalized_values),
            axis=(0, 2),
        )

        results = [
            {
                "feature_name": feature_name,
                "mean_absolute_shap": float(mean_absolute_values[index]),
            }
            for index, feature_name in enumerate(
                SECURITY_CONTEXT_FEATURE_NAMES
            )
        ]

        return sorted(
            results,
            key=lambda item: item["mean_absolute_shap"],
            reverse=True,
        )

    def class_feature_importance(
        self,
        features: list[list[float]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Calculate mean absolute SHAP importance separately per class."""

        self.model._validate_for_prediction(features)

        feature_array = np.asarray(features, dtype=np.float64)
        shap_values = self.explainer.shap_values(feature_array)

        normalized_values = self._normalize_shap_values(
            shap_values,
            sample_count=len(features),
        )

        results: dict[str, list[dict[str, Any]]] = {}

        for class_index, risk_class in enumerate(
            self.model.INDEX_TO_LABEL.values()
        ):
            importance = np.mean(
                np.abs(normalized_values[:, :, class_index]),
                axis=0,
            )

            class_results = [
                {
                    "feature_name": feature_name,
                    "mean_absolute_shap": float(importance[index]),
                }
                for index, feature_name in enumerate(
                    SECURITY_CONTEXT_FEATURE_NAMES
                )
            ]

            results[risk_class] = sorted(
                class_results,
                key=lambda item: item["mean_absolute_shap"],
                reverse=True,
            )

        return results

    def validate_additivity(
        self,
        features: list[list[float]],
        *,
        tolerance: float = 1e-4,
    ) -> dict[str, Any]:
        """
        Validate that SHAP contributions reconstruct raw model outputs.

        Checks:
            base value + sum(feature SHAP values)
                approximately equals raw class output.
        """

        if tolerance <= 0:
            raise ValueError("tolerance must be greater than zero.")

        explanations = self.explain(features)

        maximum_error = 0.0
        checks = 0

        for explanation in explanations:
            for class_explanation in explanation.class_explanations:
                reconstructed_output = (
                    class_explanation.base_value
                    + sum(
                        contribution.shap_value
                        for contribution in class_explanation.contributions
                    )
                )

                error = abs(
                    reconstructed_output
                    - class_explanation.raw_model_output
                )

                maximum_error = max(maximum_error, error)
                checks += 1

                if error > tolerance:
                    raise ValueError(
                        "SHAP additivity validation failed for "
                        f"class {class_explanation.risk_class!r}: "
                        f"error={error:.8f}, tolerance={tolerance:.8f}."
                    )

        return {
            "passed": True,
            "checks": checks,
            "maximum_absolute_error": maximum_error,
            "tolerance": tolerance,
        }

    @staticmethod
    def _normalize_shap_values(
        shap_values: Any,
        *,
        sample_count: int,
    ) -> np.ndarray:
        """
        Normalize supported SHAP multiclass output layouts to:

            (samples, features, classes)
        """

        if isinstance(shap_values, list):
            # Older SHAP versions can return one array per class.
            normalized = np.stack(shap_values, axis=-1)
        else:
            normalized = np.asarray(shap_values)

        if normalized.ndim != 3:
            raise ValueError(
                "Unexpected SHAP output dimensions: "
                f"expected 3 dimensions, got {normalized.shape}."
            )

        expected_features = SECURITY_CONTEXT_FEATURE_COUNT

        if normalized.shape == (
            sample_count,
            expected_features,
            4,
        ):
            return normalized

        if normalized.shape == (
            4,
            sample_count,
            expected_features,
        ):
            return np.transpose(normalized, (1, 2, 0))

        raise ValueError(
            "Unexpected multiclass SHAP output shape: "
            f"{normalized.shape}. "
            f"Expected ({sample_count}, {expected_features}, 4)."
        )

    @staticmethod
    def _normalize_base_values(
        base_values: Any,
    ) -> np.ndarray:
        """Normalize SHAP expected values to one value per class."""

        values = np.asarray(base_values, dtype=np.float64).reshape(-1)

        if values.shape != (4,):
            raise ValueError(
                "Unexpected SHAP base-value shape: "
                f"{values.shape}. Expected four class values."
            )

        return values
