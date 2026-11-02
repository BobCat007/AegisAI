from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


DataOrigin = Literal["synthetic", "runtime"]


class BehavioralObservation(BaseModel):
    """Aggregated behavioral metrics for one API endpoint and time window."""

    model_config = ConfigDict(extra="forbid")

    endpoint_path: str = Field(min_length=1)
    method: str = Field(min_length=1, max_length=10)

    window_seconds: float = Field(gt=0)
    request_count: int = Field(ge=1)

    unique_identity_count: int = Field(ge=0)
    unique_client_count: int = Field(ge=0)

    client_error_count: int = Field(ge=0)
    server_error_count: int = Field(ge=0)
    auth_failure_count: int = Field(ge=0)

    mean_latency_ms: float = Field(ge=0)
    latency_stddev_ms: float = Field(ge=0)

    mean_response_size_bytes: float = Field(ge=0)
    response_size_stddev_bytes: float = Field(ge=0)

    data_origin: DataOrigin = "runtime"


class BehavioralAssessmentRequest(BaseModel):
    """Batch of endpoint observations to assess."""

    observations: list[BehavioralObservation] = Field(min_length=1)


class BehavioralSignal(BaseModel):
    feature_name: str
    observed_value: float
    baseline_mean: float
    standardized_deviation: float
    direction: Literal["above_baseline", "below_baseline"]


class BehavioralAnomalyResult(BaseModel):
    endpoint_path: str
    method: str
    classification: Literal["normal", "anomalous"]
    anomaly_score: float
    signals: list[BehavioralSignal]
    data_origin: DataOrigin
    limitations: list[str]


class BehavioralAssessmentResponse(BaseModel):
    status: Literal["success"]
    model_type: Literal["isolation_forest"]
    model_available: bool
    training_data: Literal["synthetic", "runtime"]
    observations_assessed: int
    anomalous_observations: int
    results: list[BehavioralAnomalyResult]
    limitations: list[str]
