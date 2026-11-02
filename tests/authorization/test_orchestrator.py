from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from ai.authorization.models import (
    AuthorizationProbe,
    AuthorizationTestContext,
    FunctionAuthorizationPolicy,
)
from ai.authorization.orchestrator import AuthorizationTestOrchestrator


class AuthorizationHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.headers.get("Authorization", "")

        if self.path == "/resource":
            if token in {"Bearer owner-token", "Bearer user-token"}:
                body = b"resource-data"
                self.send_response(200)
            else:
                body = b"forbidden"
                self.send_response(403)

        elif self.path == "/admin":
            if token == "Bearer admin-token":
                body = b"admin-data"
                self.send_response(200)
            else:
                body = b"forbidden"
                self.send_response(403)

        else:
            body = b"not-found"
            self.send_response(404)

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def server_url(monkeypatch):
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_HOSTS", "127.0.0.1")
    monkeypatch.setenv("AEGISAI_AUTH_ALLOW_LOCAL", "true")

    server = HTTPServer(("127.0.0.1", 0), AuthorizationHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    host, port = server.server_address

    # Permit only this test server's dynamically assigned port.
    monkeypatch.setenv("AEGISAI_AUTH_ALLOWED_PORTS", str(port))

    yield f"http://{host}:{port}"

    server.shutdown()
    server.server_close()


def make_probe(url, identity, token, expected, role="user"):
    return AuthorizationProbe(
        method="GET",
        url=url,
        context=AuthorizationTestContext(
            identity=identity,
            role=role,
            authenticated=True,
        ),
        expected_outcome=expected,
        headers={"Authorization": f"Bearer {token}"},
    )


def test_orchestrator_detects_bola(server_url):
    orchestrator = AuthorizationTestOrchestrator()

    owner_probe = make_probe(
        f"{server_url}/resource",
        "user-a",
        "owner-token",
        "allow",
    )

    cross_probe = make_probe(
        f"{server_url}/resource",
        "user-b",
        "user-token",
        "deny",
    )

    finding = orchestrator.run_bola_comparison(
        owner_probe=owner_probe,
        cross_user_probe=cross_probe,
        resource_id="resource-101",
        owner_identity="user-a",
        operation="GET /resource",
    )

    assert finding.finding_type == "bola"
    assert finding.status == "suspected"
    assert finding.evidence["response_fingerprints_match"] is True


def test_orchestrator_runs_bfla_probe(server_url):
    orchestrator = AuthorizationTestOrchestrator()

    probe = make_probe(
        f"{server_url}/admin",
        "user-a",
        "user-token",
        "deny",
        role="user",
    )

    policy = FunctionAuthorizationPolicy(
        operation="GET /admin",
        permitted_roles=["admin"],
    )

    finding = orchestrator.run_bfla_probe(
        probe=probe,
        policy=policy,
    )

    assert finding.finding_type == "bfla"
    assert finding.status == "not_detected"


def test_orchestrator_rejects_same_identity_for_bola(server_url):
    orchestrator = AuthorizationTestOrchestrator()

    owner_probe = make_probe(
        f"{server_url}/resource",
        "user-a",
        "owner-token",
        "allow",
    )

    cross_probe = make_probe(
        f"{server_url}/resource",
        "user-a",
        "user-token",
        "deny",
    )

    with pytest.raises(ValueError):
        orchestrator.run_bola_comparison(
            owner_probe=owner_probe,
            cross_user_probe=cross_probe,
            resource_id="resource-101",
            owner_identity="user-a",
            operation="GET /resource",
        )


def test_orchestrator_rejects_different_resource_urls(server_url):
    orchestrator = AuthorizationTestOrchestrator()

    owner_probe = make_probe(
        f"{server_url}/resource",
        "user-a",
        "owner-token",
        "allow",
    )

    cross_probe = make_probe(
        f"{server_url}/admin",
        "user-b",
        "user-token",
        "deny",
    )

    with pytest.raises(ValueError):
        orchestrator.run_bola_comparison(
            owner_probe=owner_probe,
            cross_user_probe=cross_probe,
            resource_id="resource-101",
            owner_identity="user-a",
            operation="GET /resource",
        )
