import csv
from pathlib import Path

from ai.behavioral_intelligence import (
    BehavioralObservation,
    IsolationForestBehavioralDetector,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "behavioral_baseline.csv"
)

MODEL_PATH = (
    PROJECT_ROOT
    / "data"
    / "models"
    / "isolation_forest_behavioral.joblib"
)


def load_observations() -> list[BehavioralObservation]:
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(
            f"Behavioral dataset not found: {DATASET_PATH}. "
            "Run scripts/generate_behavioral_data.py first."
        )

    observations = []

    with DATASET_PATH.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        for row_number, row in enumerate(reader, start=2):
            try:
                observations.append(
                    BehavioralObservation(
                        endpoint_path=row["endpoint_path"],
                        method=row["method"],
                        window_seconds=float(row["window_seconds"]),
                        request_count=int(row["request_count"]),
                        unique_identity_count=int(
                            row["unique_identity_count"]
                        ),
                        unique_client_count=int(
                            row["unique_client_count"]
                        ),
                        client_error_count=int(
                            row["client_error_count"]
                        ),
                        server_error_count=int(
                            row["server_error_count"]
                        ),
                        auth_failure_count=int(
                            row["auth_failure_count"]
                        ),
                        mean_latency_ms=float(
                            row["mean_latency_ms"]
                        ),
                        latency_stddev_ms=float(
                            row["latency_stddev_ms"]
                        ),
                        mean_response_size_bytes=float(
                            row["mean_response_size_bytes"]
                        ),
                        response_size_stddev_bytes=float(
                            row["response_size_stddev_bytes"]
                        ),
                        data_origin="synthetic",
                    )
                )

            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    f"Invalid behavioral dataset row {row_number}."
                ) from error

    return observations


def train_and_save_model() -> Path:
    observations = load_observations()

    detector = IsolationForestBehavioralDetector(
        contamination=0.05,
        random_state=42,
        n_estimators=200,
    )

    detector.fit(observations)

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    detector.save(MODEL_PATH)

    print("Behavioral Isolation Forest training completed.")
    print(f"Training observations: {len(observations)}")
    print(f"Feature count: 10")
    print(f"Model artifact: {MODEL_PATH}")
    print("Training data: synthetic")
    print("Evaluation status: pipeline validation only")

    return MODEL_PATH


if __name__ == "__main__":
    train_and_save_model()
