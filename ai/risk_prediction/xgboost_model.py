from xgboost import XGBClassifier

from ai.risk_prediction.model import RiskPredictionModel


class XGBoostRiskPredictionModel(RiskPredictionModel):
    """
    XGBoost-based implementation of the risk prediction model.

    The model predicts one of the existing API risk severity labels:
    low, medium, high, or critical.
    """

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

    def fit(
        self,
        features: list[list[float]],
        labels: list[str],
    ) -> None:
        encoded_labels = [
            self.LABEL_TO_INDEX[label]
            for label in labels
        ]

        self.model.fit(
            features,
            encoded_labels,
        )

    def predict(
        self,
        features: list[list[float]],
    ) -> list[str]:
        predictions = self.model.predict(features)

        return [
            self.INDEX_TO_LABEL[int(prediction)]
            for prediction in predictions
        ]

    def predict_proba(
        self,
        features: list[list[float]],
    ) -> list[dict[str, float]]:
        probabilities = self.model.predict_proba(features)

        return [
            {
                self.INDEX_TO_LABEL[index]: float(probability)
                for index, probability in enumerate(row)
            }
            for row in probabilities
        ]
