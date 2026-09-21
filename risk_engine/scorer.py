from api_discovery.models import APIEndpoint
from risk_engine.features import extract_feature_vector
from risk_engine.models import RiskAssessment, RiskFactor


def calculate_risk(endpoint: APIEndpoint) -> RiskAssessment:
    """
    Calculate a baseline API endpoint risk score.

    This is intentionally transparent and deterministic.
    Later, the score can be complemented by an ML-based model.
    """

    score = 0.0
    reasons: list[str] = []
    risk_factors: list[RiskFactor] = []

    classification = endpoint.security_classification

    factors = [
        (
            "destructive_operation",
            30,
            classification.is_destructive,
            "Destructive operation",
        ),
        (
            "object_identifier",
            20,
            classification.has_path_parameters,
            "Object identifier in path",
        ),
        (
            "sensitive_parameter",
            25,
            classification.has_sensitive_parameters,
            "Sensitive parameter detected",
        ),
        (
            "authentication_endpoint",
            15,
            classification.is_authentication_endpoint,
            "Authentication-related endpoint",
        ),
        (
            "missing_authentication",
            10,
            not classification.is_authenticated,
            "Endpoint does not require authentication",
        ),
    ]

    for name, weight, triggered, reason in factors:
        risk_factors.append(
            RiskFactor(
                name=name,
                weight=weight,
                triggered=triggered,
            )
        )

        if triggered:
            score += weight
            reasons.append(reason)

    score = min(score, 100)

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    feature_vector = extract_feature_vector(endpoint)

    return RiskAssessment(
        score=score,
        severity=severity,
        reasons=reasons,
        risk_factors=risk_factors,
        feature_vector=feature_vector,
    )
