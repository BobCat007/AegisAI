import pytest


@pytest.fixture(autouse=True)
def disable_global_api_auth_for_tests(monkeypatch):
    """Keep application-wide API auth disabled unless a test explicitly enables it."""
    monkeypatch.setenv("AEGISAI_API_AUTH_ENABLED", "false")
