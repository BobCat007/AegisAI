from abc import ABC, abstractmethod


class RiskPredictionModel(ABC):
    """
    Abstract interface for API risk prediction models.

    Concrete implementations can later use XGBoost, neural networks,
    graph-aware models, or other learning algorithms without changing
    the rest of the application.
    """

    @abstractmethod
    def fit(
        self,
        features: list[list[float]],
        labels: list[str],
    ) -> None:
        """
        Train the model using feature vectors and risk labels.
        """
        raise NotImplementedError

    @abstractmethod
    def predict(
        self,
        features: list[list[float]],
    ) -> list[str]:
        """
        Predict a risk label for each feature vector.
        """
        raise NotImplementedError

    @abstractmethod
    def predict_proba(
        self,
        features: list[list[float]],
    ) -> list[dict[str, float]]:
        """
        Return class probabilities for each feature vector.
        """
        raise NotImplementedError
