import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app
from ai.risk_prediction.evidence import CRAPI_SECURITY_EVIDENCE


client = TestClient(app)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "sample_openapi.json"
)


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_security_reasoning_is_included_for_every_endpoint():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()
    assessments = data["endpoint_assessments"]

    assert len(assessments) == data["inventory"]["total_endpoints"]

    for assessment in assessments:
        reasoning = assessment["security_reasoning"]

        assert reasoning["path"] == assessment["path"]
        assert reasoning["method"] == assessment["method"]

        assert reasoning["overall_assessment"] in {
            "no_review_signal",
            "review_recommended",
            "documented_reference_match",
        }

        assert isinstance(reasoning["summary"], str)
        assert isinstance(reasoning["findings"], list)
        assert reasoning["vulnerabilities_confirmed"] is False
        assert isinstance(reasoning["limitations"], list)


def test_reasoning_finding_contains_required_fields():
    spec = load_fixture()

    spec["paths"]["/users/{user_id}"] = {
        "get": {
            "operationId": "get_user_by_id",
            "parameters": [
                {
                    "name": "user_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            ],
            "responses": {
                "200": {
                    "description": "User details",
                }
            },
        }
    }

    response = client.post(
        "/api/discovery/assess",
        json=spec,
    )

    assert response.status_code == 200

    data = response.json()

    assessment = next(
        item
        for item in data["endpoint_assessments"]
        if item["path"] == "/users/{user_id}"
    )

    reasoning = assessment["security_reasoning"]

    assert reasoning["overall_assessment"] == "review_recommended"
    assert len(reasoning["findings"]) > 0

    finding = reasoning["findings"][0]

    assert finding["finding_id"]
    assert finding["category"]
    assert finding["title"]
    assert finding["severity"]
    assert finding["confidence"]
    assert finding["explanation"]
    assert isinstance(finding["evidence"], list)
    assert isinstance(finding["recommended_validation"], list)


def test_documented_reference_match_appears_in_reasoning():
    evidence = CRAPI_SECURITY_EVIDENCE[0]

    spec = load_fixture()

    spec["paths"][evidence.path] = {
        evidence.method.lower(): {
            "operationId": "documented_security_reference",
            "responses": {
                "204": {
                    "description": "Operation completed",
                }
            },
        }
    }

    response = client.post(
        "/api/discovery/assess",
        json=spec,
    )

    assert response.status_code == 200

    data = response.json()

    assessment = next(
        item
        for item in data["endpoint_assessments"]
        if (
            item["path"] == evidence.path
            and item["method"].upper() == evidence.method.upper()
        )
    )

    reasoning = assessment["security_reasoning"]

    assert reasoning["overall_assessment"] == (
        "documented_reference_match"
    )

    documented_findings = [
        finding
        for finding in reasoning["findings"]
        if finding["category"] == "documented_vulnerability_reference"
    ]

    assert len(documented_findings) == 1

    finding = documented_findings[0]

    assert finding["validation_status"] == "documented_reference"

    assert reasoning["vulnerabilities_confirmed"] is False
    assert data["vulnerabilities_confirmed"] is False


def test_reasoning_does_not_claim_vulnerabilities_are_confirmed():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["vulnerabilities_confirmed"] is False

    for assessment in data["endpoint_assessments"]:
        assert (
            assessment["security_reasoning"]["vulnerabilities_confirmed"]
            is False
        )


def test_reasoning_summary_counts_match_endpoint_results():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()
    assessments = data["endpoint_assessments"]

    expected_review_count = sum(
        assessment["security_reasoning"]["overall_assessment"]
        != "no_review_signal"
        for assessment in assessments
    )

    expected_finding_count = sum(
        len(assessment["security_reasoning"]["findings"])
        for assessment in assessments
    )

    assert (
        data["summary"]["security_reasoning_endpoints_requiring_review"]
        == expected_review_count
    )

    assert (
        data["summary"]["security_reasoning_findings"]
        == expected_finding_count
    )


def test_reasoning_does_not_remove_existing_assessment_fields():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        assert "baseline_risk" in assessment
        assert "ml_risk_prediction" in assessment
        assert "security_context" in assessment
        assert "security_evidence" in assessment
        assert "security_reasoning" in assessment


def test_reasoning_is_included_when_shap_is_requested():
    response = client.post(
        "/api/discovery/assess?include_explanations=true",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        assert "security_reasoning" in assessment
