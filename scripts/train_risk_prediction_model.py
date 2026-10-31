import sys
from pathlib import Path

# Make the AegisAI project root available for imports.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ai.risk_prediction.data_loader import load_graph_training_dataset
from ai.risk_prediction.xgboost_model import XGBoostRiskPredictionModel


DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "api_graph_training_data.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "data"
    / "models"
    / "xgboost_risk_model.json"
)


def train_and_save_model() -> dict:
    """Train the final risk model, save it, and verify reloading."""

    features, labels = load_graph_training_dataset(DATASET_PATH)

    model = XGBoostRiskPredictionModel()
    model.fit(features, labels)
    model.save(MODEL_PATH)

    # Verify that the saved artifact can be loaded and used.
    loaded_model = XGBoostRiskPredictionModel.load(MODEL_PATH)

    sample_count = min(5, len(features))

    predictions = loaded_model.predict(features[:sample_count])
    probabilities = loaded_model.predict_proba(features[:sample_count])

    return {
        "dataset_path": str(DATASET_PATH),
        "model_path": str(MODEL_PATH),
        "training_samples": len(features),
        "feature_count": len(features[0]),
        "class_distribution": {
            label: labels.count(label)
            for label in sorted(set(labels))
        },
        "artifact_verified": True,
        "verification_sample_count": sample_count,
        "sample_predictions": predictions,
        "sample_probabilities": probabilities,
    }


def main() -> None:
    result = train_and_save_model()

    print("Final risk prediction model trained successfully.")
    print(f"Dataset: {result['dataset_path']}")
    print(f"Model artifact: {result['model_path']}")
    print(f"Training samples: {result['training_samples']}")
    print(f"Features per sample: {result['feature_count']}")
    print(f"Class distribution: {result['class_distribution']}")
    print(f"Artifact load verification: {result['artifact_verified']}")
    print(f"Verification predictions: {result['sample_predictions']}")


if __name__ == "__main__":
    main()

