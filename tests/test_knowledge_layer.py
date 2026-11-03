import pytest

from ai.knowledge.builder import SecurityKnowledgeBuilder
from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.normalizer import sanitize_text, sanitize_value, stable_document_id


@pytest.fixture
def builder():
    return SecurityKnowledgeBuilder()


def test_stable_ids_are_deterministic_and_scoped():
    first = stable_document_id("remediation", "source", "GET /items#r1")
    assert first == stable_document_id("remediation", "source", "GET /items#r1")
    assert first != stable_document_id("remediation", "source", "GET /items#r2")


def test_sanitizes_credentials_and_sensitive_header_values():
    value = "Authorization: Bearer abc123 api_key=secret123 password=hunter2"
    cleaned = sanitize_text(value)
    assert "abc123" not in cleaned
    assert "secret123" not in cleaned
    assert "hunter2" not in cleaned
    assert "[REDACTED]" in cleaned
    assert sanitize_value({"authorization": "Bearer abc", "safe": "ok"}) == {
        "authorization": "[REDACTED]", "safe": "ok"
    }


def test_sanitizes_nested_secret_keys_and_header_variants():
    value = {
        "request": {
            "X-API-Key": "key-value",
            "refresh_token": "refresh-value",
            "nested": [{"Set-Cookie": "session=abc"}],
        },
        "message": "client_secret=client-value",
    }
    cleaned = sanitize_value(value)
    rendered = str(cleaned)
    for secret in ("key-value", "refresh-value", "session=abc", "client-value"):
        assert secret not in rendered
    assert cleaned["request"]["X-API-Key"] == "[REDACTED]"


def test_reasoning_confirmation_requires_runtime_validated_finding(builder):
    result = {
        "path": "/users/{id}", "method": "GET", "vulnerabilities_confirmed": True,
        "findings": [
            {
                "finding_id": "F1", "title": "Static review", "validation_status": "not_validated",
                "evidence": [], "recommended_validation": [],
            },
            {
                "finding_id": "F2", "title": "Runtime review",
                "validation_status": "runtime_validated", "evidence": [],
                "recommended_validation": [],
            },
        ],
    }
    docs = builder.from_reasoning(result)
    assert [doc.confirmed for doc in docs] == [False, True]


def test_reasoning_finding_keeps_not_validated_status(builder):
    result = {
        "path": "/users/{id}", "method": "GET", "vulnerabilities_confirmed": False,
        "overall_assessment": "review_recommended", "limitations": ["No runtime proof"],
        "findings": [{
            "finding_id": "BOLA-REVIEW", "category": "bola_review",
            "title": "Review object authorization", "severity": "medium",
            "confidence": "medium", "validation_status": "not_validated",
            "explanation": "Check ownership", "evidence": [{"detail": "id parameter"}],
            "recommended_validation": ["Test with two users"],
        }],
    }
    doc = builder.from_reasoning(result)[0]
    assert doc.document_type == "reasoning_finding"
    assert doc.validation_status == "not_validated"
    assert doc.confirmed is False
    assert doc.source_reference == "GET /users/{id}#BOLA-REVIEW"


def test_authorization_evidence_is_sanitized_before_content_serialization(builder):
    finding = {
        "finding_type": "bola", "status": "suspected", "severity": "high",
        "confidence": 0.8, "title": "Possible BOLA", "description": "Review",
        "operation": "GET /orders/{id}", "evidence": {
            "response": {"authorization": "Bearer top-secret-token"},
            "api_key": "hidden-api-key",
        },
    }
    doc = builder.from_authorization_finding(finding, "case-1")
    assert "top-secret-token" not in doc.content
    assert "hidden-api-key" not in doc.content
    assert doc.metadata["evidence"]["api_key"] == "[REDACTED]"


def test_authorization_confirmation_only_from_explicit_confirmed_status(builder):
    base = {
        "finding_type": "bola", "status": "suspected", "severity": "high",
        "confidence": 0.8, "title": "Possible BOLA", "description": "Review",
        "operation": "GET /orders/{id}", "evidence": {},
    }
    suspected = builder.from_authorization_finding(base, "case-1")
    confirmed = builder.from_authorization_finding({**base, "status": "confirmed"}, "case-2")
    assert suspected.confirmed is False
    assert confirmed.confirmed is True


def test_behavioral_anomaly_is_not_vulnerability_confirmation(builder):
    doc = builder.from_behavioral_result({
        "endpoint_path": "/login", "method": "POST", "classification": "anomalous",
        "anomaly_score": -0.4, "signals": [], "data_origin": "synthetic",
        "limitations": ["Synthetic baseline"],
    }, "window-1")
    assert doc.document_type == "behavioral_anomaly"
    assert doc.confirmed is False
    assert doc.validation_status == "synthetic_observation"


def test_attack_chain_is_always_inferred_not_confirmed(builder):
    doc = builder.from_attack_chain({
        "resources": ["users", "orders"], "relationships": [], "hop_count": 1,
        "confidence": 0.9, "evidence_sources": ["openapi"],
        "interpretation": "Inferred structural path; not a confirmed exploit.",
    }, "assessment-1")
    assert doc.confirmed is False
    assert doc.validation_status == "structurally_inferred"
    assert doc.metadata["score_is_exploit_probability"] is False


def test_remediation_priority_is_not_severity(builder):
    docs = builder.from_remediation({
        "method": "DELETE", "path": "/users/{id}", "endpoint_priority_score": 70,
        "endpoint_priority_level": "high", "recommendations": [{
            "remediation_id": "R1", "finding_id": "F1", "category": "bola_review",
            "title": "Enforce ownership", "priority": "high", "endpoint": "/users/{id}",
            "objective": "Check ownership", "remediation_steps": ["Authorize"],
            "validation_steps": ["Test cross-user access"], "evidence_references": [],
            "evidence_sources": [], "limitations": [],
        }],
    })
    assert len(docs) == 1
    assert docs[0].confirmed is False
    assert docs[0].severity is None
    assert docs[0].priority == "high"


def test_document_rejects_extra_fields():
    with pytest.raises(Exception):
        KnowledgeDocument(
            document_id="x", document_type="attack_chain", title="t",
            content="c", source="s", source_reference="r", unexpected=True,
        )
