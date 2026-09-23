from typing import Literal

from pydantic import BaseModel


AuthorizationFindingStatus = Literal[
    "consistent",
    "inconsistent",
]


class AuthorizationFinding(BaseModel):
    """
    Represents the result of comparing an expected authorization outcome
    with an observed HTTP response.

    This model records the observation; it does not assign a vulnerability
    type such as BOLA or BFLA.
    """

    identity: str
    expected_outcome: Literal["allow", "deny"]
    observed_status_code: int
    status: AuthorizationFindingStatus
