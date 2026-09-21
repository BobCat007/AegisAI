from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_risk_assessment_endpoint():
    payload = {
        "path": "/users/{user_id}",
        "method": "DELETE",
        "operation_category": "delete",
        "security_classification": {
            "is_authenticated": True,
            "is_destructive": True,
            "has_path_parameters": True,
            "is_authentication_endpoint": False,
            "has_sensitive_parameters": False,
            "sensitive_parameters": [],
            "risk_indicators": [
                "Authentication required",
                "Destructive operation",
                "Object identifier in path",
            ],
        },
    }

    response = client.post(
        "/api/risk/assess",
        json=payload,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "success"

    assessment = data["risk_assessment"]

    assert assessment["score"] == 50
    assert assessment["severity"] == "medium"

    assert "Destructive operation" in assessment["reasons"]
    assert "Object identifier in path" in assessment["reasons"]

    factors = {
        factor["name"]: factor
        for factor in assessment["risk_factors"]
    }

    assert factors["destructive_operation"]["weight"] == 30
    assert factors["destructive_operation"]["triggered"] is True

    assert factors["object_identifier"]["weight"] == 20
    assert factors["object_identifier"]["triggered"] is True

    assert factors["sensitive_parameter"]["triggered"] is False
    assert factors["authentication_endpoint"]["triggered"] is False
    assert factors["missing_authentication"]["triggered"] is False

    assert assessment["feature_vector"] == [
        1.0,
        1.0,
        1.0,
        0.0,
        0.0,
        0.0,
        2.0,
    ]
