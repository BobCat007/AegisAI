from fastapi.testclient import TestClient

import backend.app.api.discovery as discovery_api
from backend.app.main import app


client = TestClient(app)


def make_openapi_spec():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Relationship Test API", "version": "1.0.0"},
        "paths": {
            "/users/{userId}": {
                "get": {
                    "operationId": "getUser",
                    "parameters": [
                        {
                            "name": "userId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            },
                        }
                    },
                }
            },
            "/users/{userId}/orders/{orderId}": {
                "get": {
                    "operationId": "getUserOrder",
                    "parameters": [
                        {
                            "name": "userId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "orderId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                    ],
                    "responses": {
                        "200": {
                            "description": "Order",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Order"}
                                }
                            },
                        }
                    },
                }
            },
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "orders": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Order"},
                        }
                    },
                },
                "Order": {
                    "type": "object",
                    "properties": {
                        "orderId": {"type": "string"},
                        "userId": {"type": "string"},
                    },
                },
            }
        },
    }


def test_assessment_includes_relationship_graph_and_attack_chain_analysis(
    monkeypatch,
):
    monkeypatch.setattr(discovery_api, "_load_risk_model", lambda: None)

    response = client.post(
        "/api/discovery/assess",
        json=make_openapi_spec(),
    )

    assert response.status_code == 200
    payload = response.json()

    assert "resource_relationship_graph" in payload
    assert "attack_chain_analysis" in payload

    relationships = payload["resource_relationship_graph"]["relationships"]
    assert relationships
    assert any(
        item["source_resource"] == "user"
        and item["target_resource"] == "order"
        for item in relationships
    )

    analysis = payload["attack_chain_analysis"]
    assert analysis["analysis_type"] == "inferred_structural_paths"
    assert analysis["not_confirmed_exploits"] is True
    assert analysis["chains"]

    chain = analysis["chains"][0]
    assert chain["hop_count"] >= 1
    assert 0.0 <= chain["confidence"] <= 1.0
    assert 0.0 <= chain["priority_score"] <= 1.0
    assert "not a confirmed exploit" in chain["interpretation"].lower()


def test_assessment_summary_reports_relationship_and_chain_counts(monkeypatch):
    monkeypatch.setattr(discovery_api, "_load_risk_model", lambda: None)

    response = client.post(
        "/api/discovery/assess",
        json=make_openapi_spec(),
    )

    assert response.status_code == 200
    payload = response.json()
    summary = payload["summary"]
    analysis = payload["attack_chain_analysis"]

    assert summary["resource_relationship_count"] == len(
        payload["resource_relationship_graph"]["relationships"]
    )
    assert summary["inferred_attack_chain_count"] == analysis["total_chains_found"]
    assert summary["attack_chain_analysis_truncated"] is analysis["truncated"]


def test_existing_assessment_fields_remain_available(monkeypatch):
    monkeypatch.setattr(discovery_api, "_load_risk_model", lambda: None)

    response = client.post(
        "/api/discovery/assess",
        json=make_openapi_spec(),
    )

    assert response.status_code == 200
    payload = response.json()

    # Existing graph and endpoint assessment contracts remain present.
    assert "security_graph" in payload
    assert "graph_features" in payload
    assert "inventory" in payload
    assert "endpoint_assessments" in payload
    assert payload["summary"]["security_context_feature_count"] > 0

    for endpoint in payload["endpoint_assessments"]:
        assert "security_context" in endpoint
        assert "feature_names" in endpoint["security_context"]
        assert "feature_vector" in endpoint["security_context"]
