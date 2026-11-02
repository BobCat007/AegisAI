from pathlib import Path
from statistics import mean, pstdev
from typing import Any

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ai.behavioral_intelligence.features import (
    BEHAVIORAL_FEATURE_NAMES,
    extract_behavioral_features,
)
from ai.behavioral_intelligence.models import (
    BehavioralAnomalyResult,
    BehavioralObservation,
    BehavioralSignal,
)


class IsolationForestBehavioralDetector:
    """Independent anomaly detector for aggregated API behavior."""

    ARTIFACT_VERSION = 1

    def __init__(
        self,
        *,
        contamination: float = 0.05,
        random_state: int = 42,
        n_estimators: int = 200,
    ) -> None:
        if not 0 < contamination <= 0.5:
            raise ValueError(
                "contamination must be greater than 0 and at most 0.5."
            )

        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators

        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1,
        )

        self.baseline_means: list[float] = []
        self.baseline_stds: list[float] = []
        self._is_fitted = False

    def fit(
        self,
        observations: list[BehavioralObservation],
    ) -> None:
        if len(observations) < 20:
            raise ValueError(
                "At least 20 observations are required to train "
                "the behavioral detector."
            )

        vectors = [
            extract_behavioral_features(item)
            for item in observations
        ]

        self.scaler.fit(vectors)
        scaled_vectors = self.scaler.transform(vectors)

        self.model.fit(scaled_vectors)

        self.baseline_means = [
            mean(vector[index] for vector in vectors)
            for index in range(len(BEHAVIORAL_FEATURE_NAMES))
        ]

        self.baseline_stds = [
            pstdev(vector[index] for vector in vectors)
            for index in range(len(BEHAVIORAL_FEATURE_NAMES))
        ]

        self._is_fitted = True

    def predict(
        self,
        observations: list[BehavioralObservation],
    ) -> list[BehavioralAnomalyResult]:
        if not self._is_fitted:
            raise RuntimeError(
                "Behavioral detector has not been fitted or loaded."
            )

        if not observations:
            raise ValueError(
                "At least one observation is required."
            )

        vectors = [
            extract_behavioral_features(item)
            for item in observations
        ]

        scaled_vectors = self.scaler.transform(vectors)

        classifications = self.model.predict(scaled_vectors)
        decision_scores = self.model.decision_function(scaled_vectors)

        results = []

        for observation, vector, classification, decision_score in zip(
            observations,
            vectors,
            classifications,
            decision_scores,
        ):
            signals = self._explain_observation(vector)

            results.append(
                BehavioralAnomalyResult(
                    endpoint_path=observation.endpoint_path,
                    method=observation.method.upper(),
                    classification=(
                        "anomalous"
                        if int(classification) == -1
                        else "normal"
                    ),
                    anomaly_score=round(
                        -float(decision_score),
                        6,
                    ),
                    signals=signals,
                    data_origin=observation.data_origin,
                    limitations=[
                        "Anomaly classification identifies unusual "
                        "behavior, not a confirmed vulnerability.",
                        "Signal deviations describe differences from "
                        "the training baseline, not causal explanations.",
                        "Detection quality depends on representative "
                        "baseline observations.",
                    ],
                )
            )

        return results

    def _explain_observation(
        self,
        vector: list[float],
    ) -> list[BehavioralSignal]:
        deviations = []

        for index, feature_name in enumerate(
            BEHAVIORAL_FEATURE_NAMES
        ):
            baseline_mean = self.baseline_means[index]
            baseline_std = self.baseline_stds[index]

            if baseline_std == 0:
                standardized_deviation = (
                    0.0
                    if vector[index] == baseline_mean
                    else float("inf")
                )
            else:
                standardized_deviation = (
                    vector[index] - baseline_mean
                ) / baseline_std

            deviations.append(
                (
                    abs(standardized_deviation),
                    index,
                    standardized_deviation,
                )
            )

        deviations.sort(
            key=lambda item: item[0],
            reverse=True,
        )

        signals = []

        for _, index, deviation in deviations[:3]:
            if deviation == 0:
                continue

            signals.append(
                BehavioralSignal(
                    feature_name=BEHAVIORAL_FEATURE_NAMES[index],
                    observed_value=round(vector[index], 6),
                    baseline_mean=round(
                        self.baseline_means[index],
                        6,
                    ),
                    standardized_deviation=(
                        round(deviation, 6)
                        if deviation != float("inf")
                        else 1_000_000.0
                    ),
                    direction=(
                        "above_baseline"
                        if deviation > 0
                        else "below_baseline"
                    ),
                )
            )

        return signals

    def save(self, path: str | Path) -> Path:
        if not self._is_fitted:
            raise RuntimeError(
                "Cannot save an unfitted behavioral detector."
            )

        artifact_path = Path(path)
        artifact_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        artifact: dict[str, Any] = {
            "artifact_version": self.ARTIFACT_VERSION,
            "feature_names": list(BEHAVIORAL_FEATURE_NAMES),
            "contamination": self.contamination,
            "random_state": self.random_state,
            "n_estimators": self.n_estimators,
            "scaler": self.scaler,
            "model": self.model,
            "baseline_means": self.baseline_means,
            "baseline_stds": self.baseline_stds,
        }

        joblib.dump(artifact, artifact_path)

        return artifact_path

    @classmethod
    def load(
        cls,
        path: str | Path,
    ) -> "IsolationForestBehavioralDetector":
        artifact_path = Path(path)

        if not artifact_path.is_file():
            raise FileNotFoundError(
                f"Behavioral model not found: {artifact_path}"
            )

        artifact = joblib.load(artifact_path)

        if artifact.get("artifact_version") != cls.ARTIFACT_VERSION:
            raise ValueError(
                "Unsupported behavioral model artifact version."
            )

        if artifact.get("feature_names") != list(
            BEHAVIORAL_FEATURE_NAMES
        ):
            raise ValueError(
                "Behavioral model feature schema mismatch."
            )

        instance = cls(
            contamination=artifact["contamination"],
            random_state=artifact["random_state"],
            n_estimators=artifact["n_estimators"],
        )

        instance.scaler = artifact["scaler"]
        instance.model = artifact["model"]
        instance.baseline_means = artifact["baseline_means"]
        instance.baseline_stds = artifact["baseline_stds"]
        instance._is_fitted = True

        return instance
