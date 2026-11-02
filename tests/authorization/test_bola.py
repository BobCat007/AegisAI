import pytest

from ai.authorization.bola import analyze_bola_access
from ai.authorization.models import AuthorizationObservation


def make_observations(
    cross_status=200,
    owner_fingerprint="resource-hash",
    cross_fingerprint="resource-hash",
):
    owner = AuthorizationObservation(
        identity="user-a",
        role="user",
        authenticated=True,
        resource_id="resource-101",
        owner_identity="user-a",
        operation="GET /api/accounts/{id}",
        expected_outcome="allow",
        status_code=200,
        response_size=128,
        response_fingerprint=owner_fingerprint,
    )

    cross_user = AuthorizationObservation(
        identity="user-b",
        role="user",
        authenticated=True,
        resource_id="resource-101",
        owner_identity="user-a",
        operation="GET /api/accounts/{id}",
        expected_outcome="deny",
        status_code=cross_status,
        response_size=128,
        response_fingerprint=cross_fingerprint,
    )

    return owner, cross_user


def test_bola_matching_fingerprints_produce_suspected_finding():
    owner, cross_user = make_observations()

    finding = analyze_bola_access(owner, cross_user)

    assert finding.finding_type == "bola"
    assert finding.status == "suspected"
    assert finding.severity == "medium"
    assert finding.confidence == 0.75
    assert finding.evidence["response_fingerprints_match"] is True


def test_bola_suspected_without_matching_fingerprints():
    owner, cross_user = make_observations(
        cross_fingerprint=None,
    )

    finding = analyze_bola_access(owner, cross_user)

    assert finding.status == "suspected"


def test_bola_not_detected_when_cross_user_is_denied():
    owner, cross_user = make_observations(
        cross_status=403,
    )

    finding = analyze_bola_access(owner, cross_user)

    assert finding.status == "not_detected"


def test_bola_inconclusive_when_owner_request_fails():
    owner, cross_user = make_observations()
    owner.status_code = 500

    finding = analyze_bola_access(owner, cross_user)

    assert finding.status == "inconclusive"


def test_bola_rejects_different_resource_ids():
    owner, cross_user = make_observations()
    cross_user.resource_id = "resource-202"

    with pytest.raises(ValueError):
        analyze_bola_access(owner, cross_user)


def test_bola_rejects_same_owner_and_cross_user_identity():
    owner, cross_user = make_observations()
    cross_user.identity = "user-a"

    with pytest.raises(ValueError):
        analyze_bola_access(owner, cross_user)

def test_bola_missing_fingerprint_is_not_complete():
    owner, cross_user = make_observations(
        cross_fingerprint=None,
    )

    finding = analyze_bola_access(owner, cross_user)

    assert finding.status == "suspected"
    assert finding.evidence["fingerprint_evidence_complete"] is False


def test_bola_truncated_matching_fingerprints_are_incomplete():
    owner, cross_user = make_observations()

    cross_user.response_truncated = True

    finding = analyze_bola_access(owner, cross_user)

    assert finding.status == "suspected"
    assert finding.confidence == 0.65
    assert finding.evidence["response_fingerprints_match"] is True
    assert finding.evidence["fingerprint_evidence_complete"] is False
