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
