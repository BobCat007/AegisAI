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
