"""
Authorization analysis components for AegisAI.
"""

from ai.authorization.bfla import analyze_bfla_access
from ai.authorization.bola import analyze_bola_access
from ai.authorization.models import (
    AuthorizationObservation,
    AuthorizationProbe,
    AuthorizationProbeResult,
    AuthorizationTestContext,
    FunctionAuthorizationPolicy,
)

__all__ = [
    "AuthorizationObservation",
    "AuthorizationProbe",
    "AuthorizationProbeResult",
    "AuthorizationTestContext",
    "FunctionAuthorizationPolicy",
    "analyze_bola_access",
    "analyze_bfla_access",
]
