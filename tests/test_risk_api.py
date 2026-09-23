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
        1.0,  # is_authenticated
        1.0,  # is_destructive
        1.0,  # has_path_parameters
        0.0,  # is_authentication_endpoint
        0.0,  # has_sensitive_parameters
        0.0,  # parameter_count
        2.0,  # path_depth
        0.0,  # has_request_body
        0.0,  # path_parameter_count
        0.0,  # query_parameter_count
        0.0,  # header_parameter_count
        0.0,  # request_body_property_count
        0.0,  # request_body_required_property_count
        0.0,  # request_body_max_depth
        0.0,  # has_response_body
        0.0,  # response_body_property_count
        0.0,  # response_body_max_depth
        0.0,  # method_get
        0.0,  # method_post
        0.0,  # method_put
        0.0,  # method_patch
        1.0,  # method_delete
        0.0,  # is_admin_context
        0.0,  # has_user_ownership_context
        0.0,  # has_other_user_context
    ]
