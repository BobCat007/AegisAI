from typing import Literal

from pydantic import BaseModel, Field


AuthorizationExpectation = Literal["allow", "deny"]


class AuthorizationTestContext(BaseModel):
    identity: str
    role: str | None = None
    authenticated: bool = False


class AuthorizationProbe(BaseModel):
    method: str
    url: str
    context: AuthorizationTestContext
    expected_outcome: AuthorizationExpectation
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body: dict | None = None


class AuthorizationProbeResult(BaseModel):
    status_code: int
    response_time_ms: float
    response_size: int
    response_fingerprint: str | None = None
    response_truncated: bool = False


class AuthorizationObservation(BaseModel):
    identity: str
    role: str | None = None
    authenticated: bool = False

    resource_id: str
    owner_identity: str
    operation: str

    expected_outcome: AuthorizationExpectation
    status_code: int = Field(ge=100, le=599)

    response_size: int = Field(default=0, ge=0)
    response_fingerprint: str | None = None
    response_truncated: bool = False


class FunctionAuthorizationPolicy(BaseModel):
    operation: str
    permitted_roles: list[str] = Field(default_factory=list)
    requires_authentication: bool = True
