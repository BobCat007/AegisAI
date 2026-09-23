from typing import Literal

from pydantic import BaseModel, Field


AuthorizationExpectation = Literal[
    "allow",
    "deny",
]


class AuthorizationTestContext(BaseModel):
    """
    Describes the identity context under which an authorization probe runs.

    The model describes the intended security context only. It does not
    determine whether the API should allow or deny the request.
    """

    identity: str
    role: str | None = None
    authenticated: bool = False


class AuthorizationProbe(BaseModel):
    """
    Describes a controlled authorization test against an API operation.

    The probe contains the request data, identity context, and expected
    authorization outcome. It does not execute the request itself.
    """

    method: str
    url: str
    context: AuthorizationTestContext
    expected_outcome: AuthorizationExpectation
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
