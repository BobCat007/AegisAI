from pydantic import BaseModel, Field


class AuthorizationProbe(BaseModel):
    """
    Describes a controlled authorization test against an API operation.

    The probe contains only the information required to describe
    the request. It does not execute the request.
    """

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body: dict | None = None


class AuthorizationProbeResult(BaseModel):
    """
    Represents the observable result of an authorization probe.
    """

    status_code: int
    response_time_ms: float
    response_size: int
