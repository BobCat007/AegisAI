from ai.authorization.findings import AuthorizationSecurityFinding
from ai.authorization.models import AuthorizationObservation


def _is_success(status_code: int) -> bool:
    return 200 <= status_code < 300


def analyze_bola_access(
    owner_observation: AuthorizationObservation,
    cross_user_observation: AuthorizationObservation,
) -> AuthorizationSecurityFinding:

    if owner_observation.resource_id != cross_user_observation.resource_id:
        raise ValueError("Both observations must reference the same resource.")

    if owner_observation.operation != cross_user_observation.operation:
        raise ValueError("Both observations must use the same operation.")

    if owner_observation.identity != owner_observation.owner_identity:
        raise ValueError("The owner observation must belong to the resource owner.")

    if cross_user_observation.owner_identity != owner_observation.owner_identity:
        raise ValueError("Both observations must identify the same resource owner.")

    if cross_user_observation.identity == owner_observation.owner_identity:
        raise ValueError("The cross-user identity must differ from the owner.")

    if owner_observation.expected_outcome != "allow":
        raise ValueError("The resource owner must be expected to have access.")

    if cross_user_observation.expected_outcome != "deny":
        raise ValueError("The cross-user identity must be expected to be denied.")

    owner_success = _is_success(owner_observation.status_code)
    cross_user_success = _is_success(cross_user_observation.status_code)

    fingerprints_available = (
        owner_observation.response_fingerprint is not None
        and cross_user_observation.response_fingerprint is not None
    )

    fingerprint_evidence_complete = (
        fingerprints_available
        and not owner_observation.response_truncated
        and not cross_user_observation.response_truncated
    )

    fingerprints_match = (
        fingerprints_available
        and owner_observation.response_fingerprint
        == cross_user_observation.response_fingerprint
    )

    evidence = {
        "owner_identity": owner_observation.identity,
        "cross_user_identity": cross_user_observation.identity,
        "resource_id": owner_observation.resource_id,
        "operation": owner_observation.operation,
        "owner_status_code": owner_observation.status_code,
        "cross_user_status_code": cross_user_observation.status_code,
        "owner_response_size": owner_observation.response_size,
        "cross_user_response_size": cross_user_observation.response_size,
        "response_fingerprints_match": fingerprints_match,
        "response_fingerprints_available": fingerprints_available,
        "owner_response_truncated": owner_observation.response_truncated,
        "cross_user_response_truncated": cross_user_observation.response_truncated,
        "fingerprint_evidence_complete": fingerprint_evidence_complete,
        "resource_metadata_verified": False,
    }

    if not owner_success:
        status = "inconclusive"
        severity = "informational"
        confidence = 0.3
        description = (
            "The resource owner's request did not succeed. "
            "The comparison cannot establish BOLA behavior."
        )

    elif not cross_user_success:
        status = "not_detected"
        severity = "informational"
        confidence = 0.9
        description = (
            "The cross-user request did not return a successful response. "
            "No BOLA behavior was detected in this comparison."
        )

    elif fingerprint_evidence_complete and fingerprints_match:
        status = "suspected"
        severity = "medium"
        confidence = 0.75
        description = (
            "The non-owner received a successful response with a matching "
            "complete response fingerprint. This suggests possible BOLA, "
            "but matching response hashes do not prove protected-data disclosure."
        )

    else:
        status = "suspected"
        severity = "medium"
        confidence = 0.65
        description = (
            "The non-owner received a successful response for a resource "
            "it was expected to be denied. The available response evidence "
            "does not establish that protected data was disclosed."
        )

    return AuthorizationSecurityFinding(
        finding_type="bola",
        status=status,
        severity=severity,
        confidence=confidence,
        title="Broken Object Level Authorization analysis",
        description=description,
        identity=cross_user_observation.identity,
        resource_id=owner_observation.resource_id,
        operation=owner_observation.operation,
        evidence=evidence,
    )
