from pathlib import Path

from xgboost import XGBClassifier

from ai.risk_prediction.model import RiskPredictionModel
from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_COUNT


class XGBoostRiskPredictionModel(RiskPredictionModel):
    """XGBoost classifier with validated model persistence."""

    LABEL_TO_INDEX = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }

    INDEX_TO_LABEL = {
        index: label
        for label, index in LABEL_TO_INDEX.items()
    }

    def __init__(self, *, random_state: int = 42) -> None:
        self.model = XGBClassifier(
            objective="multi:softprob",
            num_class=4,
            eval_metric="mlogloss",
            random_state=random_state,
            n_jobs=1,
            device="cpu",
            tree_method="hist",
        )
        self._is_fitted = False

    def fit(
        self,
        features: list[list[float]],
        labels: list[str],
    ) -> None:
        if not features:
            raise ValueError("Training requires at least one feature vector.")

        if len(features) != len(labels):
            raise ValueError(
                "Features and labels must contain the same number of samples."
            )

        self._validate_feature_vectors(features)

        invalid_labels = sorted(set(labels) - set(self.LABEL_TO_INDEX))
        if invalid_labels:
            raise ValueError(f"Unsupported risk labels: {invalid_labels}")

        self.model.fit(
            features,
            [self.LABEL_TO_INDEX[label] for label in labels],
        )
        self._is_fitted = True

    def predict(self, features: list[list[float]]) -> list[str]:
        self._validate_for_prediction(features)

        predictions = self.model.predict(features)

        return [
            self.INDEX_TO_LABEL[int(prediction)]
            for prediction in predictions
        ]

    def predict_proba(
        self,
        features: list[list[float]],
    ) -> list[dict[str, float]]:
        self._validate_for_prediction(features)

        probabilities = self.model.predict_proba(features)

        return [
            {
                self.INDEX_TO_LABEL[index]: float(probability)
                for index, probability in enumerate(row)
            }
            for row in probabilities
        ]

    def save(self, path: str | Path) -> Path:
        """Save a fitted XGBoost model to a JSON model artifact."""

        if not self._is_fitted:
            raise RuntimeError("Cannot save a model before it has been fitted.")

        artifact_path = Path(path)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)

        self.model.save_model(str(artifact_path))
        return artifact_path

    @classmethod
    def load(cls, path: str | Path) -> "XGBoostRiskPredictionModel":
        """Load a saved XGBoost model and validate its feature schema."""

        artifact_path = Path(path)

        if not artifact_path.is_file():
            raise FileNotFoundError(
                f"Risk prediction model artifact not found: {artifact_path}"
            )

        instance = cls()
        instance.model.load_model(str(artifact_path))

        expected_features = SECURITY_CONTEXT_FEATURE_COUNT
        actual_features = instance.model.n_features_in_

        if actual_features != expected_features:
            raise ValueError(
                "Model feature schema mismatch: "
                f"expected {expected_features} features, "
                f"found {actual_features}."
            )

        instance._is_fitted = True
        return instance

    @staticmethod
    def _validate_feature_vectors(
        features: list[list[float]],
    ) -> None:
        if not features:
            raise ValueError("At least one feature vector is required.")

        expected_count = SECURITY_CONTEXT_FEATURE_COUNT

        for index, vector in enumerate(features):
            if len(vector) != expected_count:
                raise ValueError(
                    f"Feature vector {index} has {len(vector)} features; "
                    f"expected {expected_count}."
                )

    def _validate_for_prediction(
        self,
        features: list[list[float]],
    ) -> None:
        if not self._is_fitted:
            raise RuntimeError(
                "Risk prediction model has not been fitted or loaded."
            )

        self._validate_feature_vectors(features)
