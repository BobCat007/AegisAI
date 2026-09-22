from api_discovery.models import APIEndpoint, SecurityClassification
from risk_engine.features import (
    FEATURE_NAMES,
    calculate_path_depth,
    calculate_request_body_max_depth,
    calculate_request_body_property_count,
    calculate_request_body_required_property_count,
    calculate_response_body_property_count,
    extract_feature_vector,
    extract_method_features,
    extract_parameter_location_features,
    extract_risk_features,
    has_response_body,
)


def test_calculate_path_depth():
    assert calculate_path_depth("/health") == 1
    assert calculate_path_depth("/users") == 1
    assert calculate_path_depth("/users/{user_id}") == 2
    assert calculate_path_depth(
        "/admin/users/{user_id}/keys"
    ) == 4


def test_extract_method_features():
    assert extract_method_features("GET") == {
        "method_get": 1.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 0.0,
    }

    assert extract_method_features("DELETE") == {
        "method_get": 0.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 1.0,
    }


def test_extract_parameter_location_features():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="GET",
        operation_category="read",
        parameters=[
            {
                "name": "user_id",
                "in": "path",
            },
            {
                "name": "search",
                "in": "query",
            },
            {
                "name": "limit",
                "in": "query",
            },
            {
                "name": "X-API-Key",
                "in": "header",
            },
        ],
    )

    features = extract_parameter_location_features(endpoint)

    assert features == {
        "path_parameter_count": 1.0,
        "query_parameter_count": 2.0,
        "header_parameter_count": 1.0,
    }


def test_calculate_request_body_property_count():
    request_body = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                        },
                        "email": {
                            "type": "string",
                        },
                        "password": {
                            "type": "string",
                        },
                        "role": {
                            "type": "string",
                        },
                    },
                }
            }
        }
    }

    assert calculate_request_body_property_count(
        request_body
    ) == 4


def test_request_body_property_count_without_properties():
    request_body = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "string",
                }
            }
        }
    }

    assert calculate_request_body_property_count(
        request_body
    ) == 0


def test_calculate_request_body_required_property_count():
    request_body = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                        },
                        "email": {
                            "type": "string",
                        },
                        "password": {
                            "type": "string",
                        },
                        "role": {
                            "type": "string",
                        },
                    },
                    "required": [
                        "username",
                        "email",
                        "password",
                    ],
                }
            }
        }
    }

    assert calculate_request_body_required_property_count(
        request_body
    ) == 3


def test_request_body_required_property_count_without_required():
    request_body = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                        }
                    },
                }
            }
        }
    }

    assert calculate_request_body_required_property_count(
        request_body
    ) == 0


def test_calculate_request_body_max_depth():
    request_body = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "user": {
                            "type": "object",
                            "properties": {
                                "profile": {
                                    "type": "object",
                                    "properties": {
                                        "name": {
                                            "type": "string",
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            }
        }
    }

    assert calculate_request_body_max_depth(
        request_body
    ) == 3


def test_request_body_max_depth_without_properties():
    request_body = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                }
            }
        }
    }

    assert calculate_request_body_max_depth(
        request_body
    ) == 0


def test_has_response_body():
    responses = {
        "200": {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                    }
                }
            },
        }
    }

    assert has_response_body(responses) is True

    assert has_response_body(
        {
            "204": {
                "description": "No content",
            }
        }
    ) is False


def test_calculate_response_body_property_count():
    responses = {
        "200": {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                            },
                            "username": {
                                "type": "string",
                            },
                            "email": {
                                "type": "string",
                            },
                            "role": {
                                "type": "string",
                            },
                        },
                    }
                }
            },
        }
    }

    assert calculate_response_body_property_count(
        responses
    ) == 4


def test_response_body_property_count_without_properties():
    responses = {
        "200": {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "string",
                    }
                }
            },
        }
    }

    assert calculate_response_body_property_count(
        responses
    ) == 0


def test_extract_risk_features():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        parameters=[
            {
                "name": "user_id",
                "in": "path",
            },
            {
                "name": "password",
                "in": "query",
            },
            {
                "name": "X-API-Key",
                "in": "header",
            },
        ],
        request_body={
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "user": {
                                "type": "object",
                                "properties": {
                                    "profile": {
                                        "type": "object",
                                        "properties": {
                                            "name": {
                                                "type": "string",
                                            }
                                        },
                                    }
                                },
                            },
                            "email": {
                                "type": "string",
                            },
                            "password": {
                                "type": "string",
                            },
                        },
                        "required": [
                            "email",
                            "password",
                        ],
                    }
                }
            }
        },
        responses={
            "200": {
                "description": "Successful response",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "id": {
                                    "type": "string",
                                }
                            },
                        }
                    }
                },
            }
        },
        security_classification=SecurityClassification(
            is_authenticated=True,
            is_destructive=True,
            has_path_parameters=True,
            is_authentication_endpoint=False,
            has_sensitive_parameters=True,
            sensitive_parameters=["password"],
        ),
    )

    features = extract_risk_features(endpoint)

    assert features == {
        "is_authenticated": 1.0,
        "is_destructive": 1.0,
        "has_path_parameters": 1.0,
        "is_authentication_endpoint": 0.0,
        "has_sensitive_parameters": 1.0,
        "parameter_count": 3.0,
        "path_depth": 2.0,
        "has_request_body": 1.0,
        "path_parameter_count": 1.0,
        "query_parameter_count": 1.0,
        "header_parameter_count": 1.0,
        "request_body_property_count": 3.0,
        "request_body_required_property_count": 2.0,
        "request_body_max_depth": 3.0,
        "has_response_body": 1.0,
        "response_body_property_count": 1.0,
        "method_get": 0.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 1.0,
    }


def test_extract_features_from_low_risk_endpoint():
    endpoint = APIEndpoint(
        path="/health",
        method="GET",
        operation_category="read",
        security_classification=SecurityClassification(
            is_authenticated=True,
        ),
    )

    features = extract_risk_features(endpoint)

    assert features == {
        "is_authenticated": 1.0,
        "is_destructive": 0.0,
        "has_path_parameters": 0.0,
        "is_authentication_endpoint": 0.0,
        "has_sensitive_parameters": 0.0,
        "parameter_count": 0.0,
        "path_depth": 1.0,
        "has_request_body": 0.0,
        "path_parameter_count": 0.0,
        "query_parameter_count": 0.0,
        "header_parameter_count": 0.0,
        "request_body_property_count": 0.0,
        "request_body_required_property_count": 0.0,
        "request_body_max_depth": 0.0,
        "has_response_body": 0.0,
        "response_body_property_count": 0.0,
        "method_get": 1.0,
        "method_post": 0.0,
        "method_put": 0.0,
        "method_patch": 0.0,
        "method_delete": 0.0,
    }


def test_feature_vector_order():
    endpoint = APIEndpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        parameters=[
            {
                "name": "user_id",
                "in": "path",
            },
            {
                "name": "password",
                "in": "query",
            },
            {
                "name": "X-API-Key",
                "in": "header",
            },
        ],
        request_body={
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "username": {
                                "type": "string",
                            },
                            "email": {
                                "type": "string",
                            },
                        },
                        "required": [
                            "username",
                        ],
                    }
                }
            }
        },
        responses={
            "200": {
                "description": "Successful response",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                        }
                    }
                },
            }
        },
        security_classification=SecurityClassification(
            is_authenticated=True,
            is_destructive=True,
            has_path_parameters=True,
            is_authentication_endpoint=False,
            has_sensitive_parameters=True,
        ),
    )

    vector = extract_feature_vector(endpoint)

    assert FEATURE_NAMES == [
        "is_authenticated",
        "is_destructive",
        "has_path_parameters",
        "is_authentication_endpoint",
        "has_sensitive_parameters",
        "parameter_count",
        "path_depth",
        "has_request_body",
        "path_parameter_count",
        "query_parameter_count",
        "header_parameter_count",
        "request_body_property_count",
        "request_body_required_property_count",
        "request_body_max_depth",
        "has_response_body",
        "response_body_property_count",
        "method_get",
        "method_post",
        "method_put",
        "method_patch",
        "method_delete",
    ]

    assert vector == [
        1.0,
        1.0,
        1.0,
        0.0,
        1.0,
        3.0,
        2.0,
        1.0,
        1.0,
        1.0,
        1.0,
        2.0,
        1.0,
        1.0,
        1.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        1.0,
    ]
