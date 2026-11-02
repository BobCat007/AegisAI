import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "sample_openapi.json"
)


def load_fixture():
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_evidence_assessment_is_included_for_every_endpoint():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        reasoning = assessment["security_reasoning"]
        evidence = reasoning["evidence_assessment"]

        assert 0 <= evidence["evidence_strength"]["score"] <= 100

        assert evidence["evidence_strength"]["level"] in (
            "low",
            "medium",
            "high",
        )

        assert evidence["validation_status"]["status"] in (
            "not_validated",
            "documented_reference",
            "runtime_validated",
        )

        priority = evidence["risk_prioritization"]

        assert priority["priority_score"] >= priority["baseline_score"]
        assert priority["vulnerabilities_confirmed"] is False

        assert evidence["vulnerabilities_confirmed"] is False


def test_baseline_risk_is_not_modified():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    for assessment in response.json()["endpoint_assessments"]:
        baseline = assessment["baseline_risk"]
        priority = assessment["security_reasoning"][
            "evidence_assessment"
        ]["risk_prioritization"]

        assert priority["baseline_score"] == baseline["score"]
        assert priority["baseline_severity"] == baseline["severity"]


def test_evidence_summary_fields_are_present():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    summary = response.json()["summary"]

    assert "high_evidence_strength_endpoints" in summary
    assert "high_or_critical_priority_endpoints" in summary
    assert "average_evidence_strength" in summary
