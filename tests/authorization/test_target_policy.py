import socket

import pytest

from ai.authorization.target_policy import AuthorizationTargetPolicy


def fake_records(address):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (address, 8000),
        )
    ]


def test_target_policy_accepts_allowlisted_loopback(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_HOSTS", "127.0.0.1")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", "8000")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOW_LOCAL", "true")

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: fake_records("127.0.0.1"),
    )

    policy = AuthorizationTargetPolicy()

    assert policy.validate("http://127.0.0.1:8000/test") == ["127.0.0.1"]


def test_target_policy_rejects_unapproved_port(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_HOSTS", "127.0.0.1")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", "8000")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOW_LOCAL", "true")

    policy = AuthorizationTargetPolicy()

    with pytest.raises(ValueError, match="port allowlist"):
        policy.validate("http://127.0.0.1:9000/test")


def test_local_mode_rejects_private_non_loopback_address(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_HOSTS", "internal.example")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", "8000")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOW_LOCAL", "true")

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: fake_records("192.168.1.10"),
    )

    policy = AuthorizationTargetPolicy()

    with pytest.raises(ValueError, match="loopback"):
        policy.validate("http://internal.example:8000/test")


def test_public_only_mode_rejects_loopback(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_HOSTS", "127.0.0.1")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", "8000")
    monkeypatch.delenv("AEGISAI_AUTH_ALLOW_LOCAL", raising=False)

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: fake_records("127.0.0.1"),
    )

    policy = AuthorizationTargetPolicy()

    with pytest.raises(ValueError, match="non-public"):
        policy.validate("http://127.0.0.1:8000/test")


def test_target_policy_rejects_non_allowlisted_host(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_HOSTS", "localhost")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", "8000")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOW_LOCAL", "true")

    policy = AuthorizationTargetPolicy()

    with pytest.raises(ValueError, match="allowlist"):
        policy.validate("http://127.0.0.1:8000/test")


def test_target_policy_rejects_invalid_port_configuration(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", "8000,invalid")

    with pytest.raises(ValueError, match="invalid port"):
        AuthorizationTargetPolicy()


def test_target_policy_rejects_out_of_range_port(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", "70000")

    with pytest.raises(ValueError, match="between 1 and 65535"):
        AuthorizationTargetPolicy()
