from ai.risk_prediction.evidence import (
    CRAPI_SECURITY_EVIDENCE,
    SecurityEvidence,
)


def test_security_evidence_defaults_confidence_and_references():
    evidence = SecurityEvidence(
        source="OWASP crAPI",
        vulnerability_type="BFLA",
        path="/identity/api/v2/admin/videos/{video_id}",
        method="DELETE",
        description="Documented broken function-level authorization.",
    )

    assert evidence.source == "OWASP crAPI"
    assert evidence.vulnerability_type == "BFLA"
    assert evidence.path == "/identity/api/v2/admin/videos/{video_id}"
    assert evidence.method == "DELETE"
    assert evidence.confidence == "documented"
    assert evidence.references == []


def test_security_evidence_preserves_references():
    evidence = SecurityEvidence(
        source="OWASP crAPI",
        vulnerability_type="BOLA",
        path="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        description="Documented unauthorized vehicle-location access.",
        confidence="documented",
        references=["OWASP crAPI"],
    )

    assert evidence.references == ["OWASP crAPI"]


def test_crapi_evidence_contains_bfla_finding():
    evidence = next(
        item
        for item in CRAPI_SECURITY_EVIDENCE
        if item.vulnerability_type == "BFLA"
    )

    assert evidence.path == "/identity/api/v2/admin/videos/{video_id}"
    assert evidence.method == "DELETE"
    assert evidence.confidence == "documented"


def test_crapi_evidence_contains_bola_finding():
    evidence = next(
        item
        for item in CRAPI_SECURITY_EVIDENCE
        if item.vulnerability_type == "BOLA"
    )

    assert evidence.path == "/identity/api/v2/vehicle/{vehicleId}/location"
    assert evidence.method == "GET"
    assert evidence.confidence == "documented"
