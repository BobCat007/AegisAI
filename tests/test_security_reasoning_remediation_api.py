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


def test_remediation_plan_is_included_for_every_endpoint():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        reasoning = assessment["security_reasoning"]
        plan = reasoning["remediation_plan"]

        assert plan["path"] == assessment["path"]
        assert plan["method"] == assessment["method"]
        assert plan["total_recommendations"] == len(
            plan["recommendations"]
        )

        for recommendation in plan["recommendations"]:
            assert recommendation["finding_id"]
            assert recommendation["remediation_steps"]
            assert recommendation["validation_steps"]
            assert recommendation["limitations"]


def test_remediation_recommendations_reference_existing_findings():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    for assessment in response.json()["endpoint_assessments"]:
        reasoning = assessment["security_reasoning"]

        finding_ids = {
            finding["finding_id"]
            for finding in reasoning["findings"]
        }

        remediation_ids = {
            item["finding_id"]
            for item in reasoning["remediation_plan"][
                "recommendations"
            ]
        }

        assert remediation_ids.issubset(finding_ids)


def test_remediation_summary_counts_match_api_results():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    expected_total = sum(
        assessment["security_reasoning"]["remediation_plan"][
            "total_recommendations"
        ]
        for assessment in data["endpoint_assessments"]
    )

    expected_high_priority = sum(
        recommendation["priority"] in ("high", "critical")
        for assessment in data["endpoint_assessments"]
        for recommendation in assessment["security_reasoning"][
            "remediation_plan"
        ]["recommendations"]
    )

    assert data["summary"]["remediation_recommendations"] == expected_total

    assert (
        data["summary"]["high_or_critical_remediation_recommendations"]
        == expected_high_priority
    )
