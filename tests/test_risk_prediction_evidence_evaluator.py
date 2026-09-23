from ai.risk_prediction.evidence import CRAPI_SECURITY_EVIDENCE
from ai.risk_prediction.evidence_evaluator import (
    EvidenceEvaluation,
    evaluate_against_evidence,
)


def test_evaluator_matches_bfla_endpoint():
    result = evaluate_against_evidence(
        path="/identity/api/v2/admin/videos/{video_id}",
        method="DELETE",
        evidence=CRAPI_SECURITY_EVIDENCE,
        predicted_label="medium",
    )

    assert isinstance(result, EvidenceEvaluation)
    assert result.has_security_evidence is True
    assert result.vulnerability_types == ["BFLA"]
    assert result.predicted_label == "medium"


def test_evaluator_matches_bola_endpoint():
    result = evaluate_against_evidence(
        path="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        evidence=CRAPI_SECURITY_EVIDENCE,
        predicted_label="low",
    )

    assert result.has_security_evidence is True
    assert result.vulnerability_types == ["BOLA"]
    assert result.predicted_label == "low"


def test_evaluator_returns_no_match_for_unlisted_endpoint():
    result = evaluate_against_evidence(
        path="/identity/api/v2/example/{id}",
        method="GET",
        evidence=CRAPI_SECURITY_EVIDENCE,
        predicted_label="low",
    )

    assert result.has_security_evidence is False
    assert result.vulnerability_types == []
    assert result.predicted_label == "low"


def test_evaluator_method_matching_is_case_insensitive():
    result = evaluate_against_evidence(
        path="/identity/api/v2/admin/videos/{video_id}",
        method="delete",
        evidence=CRAPI_SECURITY_EVIDENCE,
        predicted_label="medium",
    )

    assert result.has_security_evidence is True
    assert result.method == "DELETE"
    assert result.predicted_label == "medium"


def test_evaluator_allows_missing_prediction():
    result = evaluate_against_evidence(
        path="/identity/api/v2/admin/videos/{video_id}",
        method="DELETE",
        evidence=CRAPI_SECURITY_EVIDENCE,
    )

    assert result.predicted_label is None
    assert result.has_security_evidence is True
