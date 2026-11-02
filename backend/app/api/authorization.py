import hmac
import os
import ssl

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from ai.authorization.models import (
    AuthorizationProbe,
    FunctionAuthorizationPolicy,
)
from ai.authorization.orchestrator import AuthorizationTestOrchestrator
from ai.authorization.target_policy import AuthorizationTargetPolicy


router = APIRouter(
    prefix="/api/authorization",
    tags=["Authorization Analysis"],
)


class BOLARequest(BaseModel):
    owner_probe: AuthorizationProbe
    cross_user_probe: AuthorizationProbe
    resource_id: str
    owner_identity: str
    operation: str


class BFLARequest(BaseModel):
    probe: AuthorizationProbe
    policy: FunctionAuthorizationPolicy
    resource_id: str = "not-applicable"


class AuthorizationAssessmentResponse(BaseModel):
    status: str
    finding: dict
    limitations: list[str] = Field(default_factory=list)


def require_authorization_api_key(
    api_key: str | None = Header(
        default=None,
        alias="X-AegisAI-Auth-Key",
    ),
) -> None:
    enabled = os.getenv(
        "AEGISAI_AUTH_API_ENABLED", ""
    ).lower() == "true"

    if not enabled:
        raise HTTPException(
            status_code=503,
            detail="Authorization assessment API is disabled.",
        )

    configured_key = os.getenv("AEGISAI_AUTH_API_KEY", "")

    if not configured_key:
        raise HTTPException(
            status_code=503,
            detail="Authorization assessment API key is not configured.",
        )

    if not api_key or not hmac.compare_digest(api_key, configured_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing authorization API key.",
        )


def get_orchestrator() -> AuthorizationTestOrchestrator:
    return AuthorizationTestOrchestrator(
        target_policy=AuthorizationTargetPolicy(),
    )


def handle_assessment_error(exc: Exception) -> None:
    if isinstance(exc, ValueError):
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    if isinstance(exc, TimeoutError):
        raise HTTPException(
            status_code=504,
            detail="Authorization target timed out.",
        ) from exc

    if isinstance(exc, (ConnectionError, OSError, ssl.SSLError)):
        raise HTTPException(
            status_code=502,
            detail="Authorization target connection or TLS failure.",
        ) from exc

    raise HTTPException(
        status_code=500,
        detail="Authorization assessment failed.",
    ) from exc


@router.post(
    "/bola/assess",
    response_model=AuthorizationAssessmentResponse,
)
def assess_bola(
    request: BOLARequest,
    api_key: str | None = Header(
        default=None,
        alias="X-AegisAI-Auth-Key",
    ),
):
    require_authorization_api_key(api_key)

    try:
        finding = get_orchestrator().run_bola_comparison(
            owner_probe=request.owner_probe,
            cross_user_probe=request.cross_user_probe,
            resource_id=request.resource_id,
            owner_identity=request.owner_identity,
            operation=request.operation,
        )
    except (ValueError, TimeoutError, ConnectionError, OSError, ssl.SSLError) as exc:
        handle_assessment_error(exc)

    return {
        "status": "success",
        "finding": finding.model_dump(),
        "limitations": [
            "The result is based on the supplied owner and cross-user probes.",
            "Response fingerprints are supporting evidence, not proof of identical protected data.",
            "Matching fingerprints alone cannot confirm protected-data disclosure.",
            "Truncated response bodies limit fingerprint comparison.",
            "Only authorized test identities and targets should be used.",
        ],
    }


@router.post(
    "/bfla/assess",
    response_model=AuthorizationAssessmentResponse,
)
def assess_bfla(
    request: BFLARequest,
    api_key: str | None = Header(
        default=None,
        alias="X-AegisAI-Auth-Key",
    ),
):
    require_authorization_api_key(api_key)

    try:
        finding = get_orchestrator().run_bfla_probe(
            probe=request.probe,
            policy=request.policy,
            resource_id=request.resource_id,
        )
    except (ValueError, TimeoutError, ConnectionError, OSError, ssl.SSLError) as exc:
        handle_assessment_error(exc)

    return {
        "status": "success",
        "finding": finding.model_dump(),
        "limitations": [
            "The result depends on the supplied role and function policy.",
            "A response status alone cannot establish the full authorization policy.",
            "Only authorized test identities and targets should be used.",
        ],
    }
