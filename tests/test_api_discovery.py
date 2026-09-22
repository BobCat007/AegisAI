import json
from pathlib import Path

from api_discovery.service import discover_api


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "sample_openapi.json"
)


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_api_discovery():
    spec = load_fixture()

    inventory = discover_api(spec)

    assert inventory.title == "AegisAI Demo API"
    assert inventory.version == "1.0.0"
    assert inventory.openapi_version == "3.0.3"
    assert inventory.total_endpoints == 5


def test_endpoint_discovery():
    spec = load_fixture()

    inventory = discover_api(spec)

    endpoint_paths = {
        endpoint.path
        for endpoint in inventory.endpoints
    }

    assert "/users" in endpoint_paths
    assert "/users/{user_id}" in endpoint_paths
    assert "/auth/login" in endpoint_paths


def test_http_methods():
    spec = load_fixture()

    inventory = discover_api(spec)

    methods = {
        endpoint.method
        for endpoint in inventory.endpoints
    }

    assert "GET" in methods
    assert "POST" in methods
    assert "DELETE" in methods


def test_security_classification():
    spec = load_fixture()

    inventory = discover_api(spec)

    delete_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users/{user_id}"
        and endpoint.method == "DELETE"
    )

    login_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/auth/login"
        and endpoint.method == "POST"
    )

    assert delete_endpoint.security_classification.is_destructive is True
    assert (
        delete_endpoint.security_classification.has_path_parameters
        is True
    )
    assert (
        "Destructive operation"
        in delete_endpoint.security_classification.risk_indicators
    )

    assert (
        login_endpoint.security_classification.is_authentication_endpoint
        is True
    )

def test_object_identifier_name_detection():
    spec = load_fixture()

    inventory = discover_api(spec)

    user_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users/{user_id}"
        and endpoint.method == "DELETE"
    )

    collection_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users"
        and endpoint.method == "GET"
    )

    assert (
        user_endpoint.security_classification.object_identifier_names
        == ["user_id"]
    )

    assert (
        collection_endpoint.security_classification.object_identifier_names
        == []
    )

def test_authentication_detection():
    spec = load_fixture()

    inventory = discover_api(spec)

    users_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users"
        and endpoint.method == "GET"
    )

    login_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/auth/login"
        and endpoint.method == "POST"
    )

    assert users_endpoint.security_classification.is_authenticated is True
    assert (
        "Authentication required"
        in users_endpoint.security_classification.risk_indicators
    )

    assert login_endpoint.security_classification.is_authenticated is False


def test_sensitive_parameter_detection():
    spec = load_fixture()

    inventory = discover_api(spec)

    create_user_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users"
        and endpoint.method == "POST"
    )

    login_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/auth/login"
        and endpoint.method == "POST"
    )

    assert (
        create_user_endpoint.security_classification.has_sensitive_parameters
        is True
    )

    assert (
        create_user_endpoint.security_classification.sensitive_parameters
        == ["password"]
    )

    assert (
        "Sensitive parameter detected"
        in create_user_endpoint.security_classification.risk_indicators
    )

    assert (
        login_endpoint.security_classification.has_sensitive_parameters
        is True
    )

    assert (
        login_endpoint.security_classification.sensitive_parameters
        == ["password"]
    )


def test_sensitive_request_body_property_detection():
    spec = load_fixture()

    spec["paths"]["/request-body-secret"] = {
        "post": {
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "username": {
                                    "type": "string",
                                },
                                "password": {
                                    "type": "string",
                                },
                            },
                        }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "Success",
                }
            },
        }
    }

    inventory = discover_api(spec)

    endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/request-body-secret"
        and endpoint.method == "POST"
    )

    assert (
        endpoint.security_classification.has_sensitive_parameters
        is True
    )

    assert (
        endpoint.security_classification.sensitive_parameters
        == ["password"]
    )

    assert (
        "Sensitive parameter detected"
        in endpoint.security_classification.risk_indicators
    )


def test_non_sensitive_request_body_properties_are_not_flagged():
    spec = load_fixture()

    spec["paths"]["/request-body-normal"] = {
        "post": {
            "requestBody": {
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
                        }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "Success",
                }
            },
        }
    }

    inventory = discover_api(spec)

    endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/request-body-normal"
        and endpoint.method == "POST"
    )

    assert (
        endpoint.security_classification.has_sensitive_parameters
        is False
    )

    assert (
        endpoint.security_classification.sensitive_parameters
        == []
    )

def test_sensitive_response_properties_are_not_duplicated():
    spec = load_fixture()

    spec["paths"]["/duplicate-response-token"] = {
        "get": {
            "responses": {
                "200": {
                    "description": "Success",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "access_token": {
                                        "type": "string",
                                    },
                                },
                            }
                        }
                    },
                },
                "201": {
                    "description": "Created",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "access_token": {
                                        "type": "string",
                                    },
                                },
                            }
                        }
                    },
                },
            }
        }
    }

    inventory = discover_api(spec)

    endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/duplicate-response-token"
        and endpoint.method == "GET"
    )

    assert (
        endpoint.security_classification.sensitive_response_fields
        == ["access_token"]
    )

def test_sensitive_response_property_detection():
    spec = load_fixture()

    spec["paths"]["/response-token"] = {
        "get": {
            "responses": {
                "200": {
                    "description": "Success",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "user_id": {
                                        "type": "string",
                                    },
                                    "access_token": {
                                        "type": "string",
                                    },
                                },
                            }
                        }
                    },
                }
            },
        }
    }

    inventory = discover_api(spec)

    endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/response-token"
        and endpoint.method == "GET"
    )

    assert (
        endpoint.security_classification.has_sensitive_response_fields
        is True
    )

    assert (
        endpoint.security_classification.sensitive_response_fields
        == ["access_token"]
    )

def test_operation_categories():
    spec = load_fixture()

    inventory = discover_api(spec)

    list_users = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users"
        and endpoint.method == "GET"
    )

    create_user = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users"
        and endpoint.method == "POST"
    )

    delete_user = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users/{user_id}"
        and endpoint.method == "DELETE"
    )

    assert list_users.operation_category == "read"
    assert create_user.operation_category == "create/action"
    assert delete_user.operation_category == "delete"

def test_object_access_pattern_detection():
    spec = load_fixture()

    inventory = discover_api(spec)

    collection_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users"
        and endpoint.method == "GET"
    )

    object_endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users/{user_id}"
        and endpoint.method == "DELETE"
    )

    assert (
        collection_endpoint.security_classification.object_access_pattern
        == "collection"
    )

    assert (
        object_endpoint.security_classification.object_access_pattern
        == "object"
    )
def test_nested_object_access_pattern_detection():
    spec = load_fixture()

    spec["paths"]["/users/{user_id}/orders"] = {
        "get": {
            "responses": {
                "200": {
                    "description": "Success",
                }
            }
        }
    }

    inventory = discover_api(spec)

    endpoint = next(
        endpoint
        for endpoint in inventory.endpoints
        if endpoint.path == "/users/{user_id}/orders"
        and endpoint.method == "GET"
    )

    assert (
        endpoint.security_classification.object_access_pattern
        == "nested_object"
    )

    assert (
        endpoint.security_classification.object_identifier_names
        == ["user_id"]
    )

def test_object_operation_surface():
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Operation Surface Test API",
            "version": "1.0.0",
        },
        "paths": {
            "/users/{user_id}": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "Success",
                        }
                    }
                },
                "put": {
                    "responses": {
                        "200": {
                            "description": "Success",
                        }
                    }
                },
                "delete": {
                    "responses": {
                        "204": {
                            "description": "Deleted",
                        }
                    }
                },
            }
        },
    }

    inventory = discover_api(spec)

    user_object_operations = {
        endpoint.method
        for endpoint in inventory.endpoints
        if endpoint.path == "/users/{user_id}"
    }

    assert user_object_operations == {
        "GET",
        "PUT",
        "DELETE",
    }

    assert len(inventory.object_operation_surfaces) == 1

    surface = inventory.object_operation_surfaces[0]

    assert surface.path_template == "/users/{user_id}"

    assert surface.object_identifier_names == [
        "user_id"
    ]

    assert set(surface.operations) == {
        "GET",
        "PUT",
        "DELETE",
    }

    assert surface.has_read_operation is True
    assert surface.has_write_operation is True
    assert surface.has_delete_operation is True
