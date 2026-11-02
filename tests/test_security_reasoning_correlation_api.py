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


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_correlation_is_included_for_every_endpoint():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        reasoning = assessment["security_reasoning"]
        correlation = reasoning["evidence_correlation"]

        assert isinstance(correlation["groups"], list)
        assert isinstance(correlation["relationships"], list)
        assert correlation["total_evidence_sources"] >= 0
        assert correlation["total_relationships"] >= 0
        assert correlation["total_relationships"] == len(
            correlation["relationships"]
        )

        assert correlation["limitations"]


def test_correlation_does_not_merge_assessment_graph_scope():
    response = client.post(
        "/api/discovery/assess?include_explanations=true",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        correlation = assessment["security_reasoning"][
            "evidence_correlation"
        ]

        for group in correlation["groups"]:
            assert group["scope"] != "assessment_graph"


def test_ml_prediction_and_shap_share_dependency_group_when_available():
    response = client.post(
        "/api/discovery/assess?include_explanations=true",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    for assessment in data["endpoint_assessments"]:
        correlation = assessment["security_reasoning"][
            "evidence_correlation"
        ]

        sources = [
            source
            for group in correlation["groups"]
            for source in group["evidence"]
        ]

        ml_sources = [
            source
            for source in sources
            if source["source_type"] == "ml_prediction"
        ]

        shap_sources = [
            source
            for source in sources
            if source["source_type"] == "shap"
        ]

        if assessment["ml_risk_prediction"]["available"]:
            assert len(ml_sources) == 1
            assert ml_sources[0]["dependency_group"] == (
                "xgboost-risk-model"
            )

        if assessment.get("shap_explanation", {}).get("available"):
            assert shap_sources
            assert all(
                source["dependency_group"] == "xgboost-risk-model"
                for source in shap_sources
            )

        if ml_sources and shap_sources:
            model_relationships = [
                relationship
                for relationship in correlation["relationships"]
                if (
                    relationship["source_id_a"] == ml_sources[0]["source_id"]
                    or relationship["source_id_b"] == ml_sources[0]["source_id"]
                )
            ]

            assert model_relationships
            assert all(
                relationship["relationship"] == "explains"
                for relationship in model_relationships
            )
            assert all(
                relationship["independent_sources"] is False
                for relationship in model_relationships
            )


def test_correlation_does_not_change_vulnerability_confirmation():
    response = client.post(
        "/api/discovery/assess",
        json=load_fixture(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["vulnerabilities_confirmed"] is False

    for assessment in data["endpoint_assessments"]:
        reasoning = assessment["security_reasoning"]

        assert reasoning["vulnerabilities_confirmed"] is False
        assert "evidence_correlation" in reasoning
