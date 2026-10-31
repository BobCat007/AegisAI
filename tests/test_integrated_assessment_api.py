import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app
from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES


client = TestClient(app)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "sample_openapi.json"
)


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_integrated_assessment_returns_success():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"
    assert data["assessment_type"] == "openapi_static_analysis"
    assert data["vulnerabilities_confirmed"] is False


def test_integrated_assessment_includes_inventory_and_graph():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["inventory"]["title"] == "AegisAI Demo API"
    assert data["inventory"]["total_endpoints"] == 5

    assert "objects" in data["security_graph"]
    assert "operations" in data["security_graph"]
    assert isinstance(data["graph_features"], dict)


def test_integrated_assessment_covers_every_endpoint():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assessments = data["endpoint_assessments"]

    assert len(assessments) == data["inventory"]["total_endpoints"]
    assert data["summary"]["assessed_endpoints"] == len(assessments)

    for assessment in assessments:
        assert assessment["path"]
        assert assessment["method"]

        baseline = assessment["baseline_risk"]

        assert 0 <= baseline["score"] <= 100
        assert baseline["severity"] in {
            "low",
            "medium",
            "high",
            "critical",
        }


def test_security_context_vectors_match_the_feature_schema():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["summary"]["security_context_feature_count"]
        == len(SECURITY_CONTEXT_FEATURE_NAMES)
    )

    for assessment in data["endpoint_assessments"]:
        context = assessment["security_context"]

        assert context["feature_names"] == list(
            SECURITY_CONTEXT_FEATURE_NAMES
        )

        assert len(context["feature_vector"]) == len(
            SECURITY_CONTEXT_FEATURE_NAMES
        )

        assert all(
            isinstance(value, (int, float))
            for value in context["feature_vector"]
        )


def test_integrated_assessment_rejects_invalid_specification():
    response = client.post(
        "/api/discovery/assess",
        json={"openapi": "3.0.3", "paths": "invalid"},
    )

    assert response.status_code == 400
    assert response.json()["detail"].startswith(
        "Unable to assess OpenAPI specification:"
    )
