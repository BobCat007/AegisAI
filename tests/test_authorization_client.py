import hashlib
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlsplit

import pytest

from ai.authorization.client import AuthorizationProbeClient
from ai.authorization.models import (
    AuthorizationProbe,
    AuthorizationTestContext,
)


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.com/unapproved")
            self.end_headers()
            return

        response_body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        response_body = b"created"
        self.send_response(201)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        pass


def start_server():
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def make_probe(url, method="GET"):
    return AuthorizationProbe(
        method=method,
        url=url,
        context=AuthorizationTestContext(identity="anonymous"),
        expected_outcome="allow",
    )


def resolve_local_address(url):
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    return sorted({
        record[4][0]
        for record in socket.getaddrinfo(
            parsed.hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    })


def execute_local(client, probe):
    return client.execute(
        probe,
        resolved_addresses=resolve_local_address(probe.url),
    )


def test_authorization_probe_client_executes_request():
    server = start_server()

    try:
        host, port = server.server_address
        client = AuthorizationProbeClient(timeout_seconds=5.0)

        result = execute_local(
            client,
            make_probe(f"http://{host}:{port}/health"),
        )

        assert result.status_code == 200
        assert result.response_size == 5
        assert result.response_time_ms >= 0

    finally:
        server.shutdown()
        server.server_close()


def test_authorization_probe_generates_response_fingerprint():
    server = start_server()

    try:
        host, port = server.server_address
        client = AuthorizationProbeClient(timeout_seconds=5.0)

        result = execute_local(
            client,
            make_probe(f"http://{host}:{port}/health"),
        )

        expected = hashlib.sha256(b"hello").hexdigest()
        assert result.response_fingerprint == expected

    finally:
        server.shutdown()
        server.server_close()


def test_authorization_probe_fingerprints_differ_for_different_responses():
    server = start_server()

    try:
        host, port = server.server_address
        client = AuthorizationProbeClient(timeout_seconds=5.0)

        first = execute_local(
            client,
            make_probe(f"http://{host}:{port}/health", "GET"),
        )
        second = execute_local(
            client,
            make_probe(f"http://{host}:{port}/create", "POST"),
        )

        assert first.response_fingerprint != second.response_fingerprint

    finally:
        server.shutdown()
        server.server_close()


def test_authorization_probe_does_not_follow_redirects():
    server = start_server()

    try:
        host, port = server.server_address
        client = AuthorizationProbeClient(timeout_seconds=5.0)

        result = execute_local(
            client,
            make_probe(f"http://{host}:{port}/redirect"),
        )

        assert result.status_code == 302

    finally:
        server.shutdown()
        server.server_close()


def test_authorization_probe_rejects_host_header_override():
    server = start_server()

    try:
        host, port = server.server_address
        probe = make_probe(f"http://{host}:{port}/health")
        probe.headers = {"Host": "attacker.example"}

        client = AuthorizationProbeClient(timeout_seconds=5.0)

        with pytest.raises(ValueError, match="Host"):
            execute_local(client, probe)

    finally:
        server.shutdown()
        server.server_close()


def test_response_body_is_bounded_and_truncation_reported():
    class LargeHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"x" * 100
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), LargeHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        client = AuthorizationProbeClient(
            timeout_seconds=5.0,
            max_response_bytes=16,
        )

        result = client.execute(
            make_probe(f"http://{host}:{port}/large"),
            resolved_addresses=["127.0.0.1"],
        )

        assert result.status_code == 200
        assert result.response_size == 16
        assert result.response_truncated is True

    finally:
        server.shutdown()
        server.server_close()


def test_response_under_limit_is_not_truncated():
    server = start_server()

    try:
        host, port = server.server_address
        client = AuthorizationProbeClient(
            timeout_seconds=5.0,
            max_response_bytes=100,
        )

        result = client.execute(
            make_probe(f"http://{host}:{port}/health"),
            resolved_addresses=["127.0.0.1"],
        )

        assert result.response_size == 5
        assert result.response_truncated is False

    finally:
        server.shutdown()
        server.server_close()


def test_http_non_default_port_is_in_host_header():
    class HostHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.headers.get("Host", "").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), HostHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        client = AuthorizationProbeClient(timeout_seconds=5.0)

        result = client.execute(
            make_probe(f"http://{host}:{port}/"),
            resolved_addresses=["127.0.0.1"],
        )

        assert result.status_code == 200
        assert result.response_fingerprint == hashlib.sha256(
            f"{host}:{port}".encode()
        ).hexdigest()

    finally:
        server.shutdown()
        server.server_close()


def test_client_rejects_invalid_pinned_address():
    client = AuthorizationProbeClient()

    with pytest.raises(ValueError):
        client.execute(
            make_probe("http://127.0.0.1/"),
            resolved_addresses=["not-an-ip"],
        )

def test_client_rejects_header_newline_injection():
    client = AuthorizationProbeClient()

    probe = make_probe("http://127.0.0.1/health")
    probe.headers = {"X-Test": "safe\r\nHost: attacker.example"}

    with pytest.raises(ValueError, match="CR or LF"):
        client.execute(probe, ["127.0.0.1"])


def test_client_rejects_invalid_header_name():
    client = AuthorizationProbeClient()

    probe = make_probe("http://127.0.0.1/health")
    probe.headers = {"Bad Header": "value"}

    with pytest.raises(ValueError, match="header name"):
        client.execute(probe, ["127.0.0.1"])


def test_client_rejects_non_string_header_value():
    client = AuthorizationProbeClient()

    probe = make_probe("http://127.0.0.1/health")
    probe.headers = {"X-Test": 123}

    with pytest.raises(ValueError, match="strings"):
        client.execute(probe, ["127.0.0.1"])
