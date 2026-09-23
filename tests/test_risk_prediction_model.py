import pytest

from ai.risk_prediction.model import RiskPredictionModel


class IncompleteRiskModel(RiskPredictionModel):
    pass


def test_risk_prediction_model_is_abstract():
    with pytest.raises(TypeError):
        IncompleteRiskModel()


def test_risk_prediction_model_defines_required_methods():
    required_methods = {
        "fit",
        "predict",
        "predict_proba",
    }

    assert required_methods.issubset(
        set(RiskPredictionModel.__abstractmethods__)
    )
