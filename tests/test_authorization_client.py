from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from ai.authorization.client import AuthorizationProbeClient
from ai.authorization.models import (
    AuthorizationProbe,
    AuthorizationTestContext,
)


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, format, *args):
        pass


def test_authorization_probe_client_executes_request():
    server = HTTPServer(
        ("127.0.0.1", 0),
        MockHandler,
    )

    thread = Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    try:
        host, port = server.server_address

        probe = AuthorizationProbe(
            method="GET",
            url=f"http://{host}:{port}/health",
            context=AuthorizationTestContext(
                identity="anonymous",
            ),
            expected_outcome="allow",
        )

        client = AuthorizationProbeClient(
            timeout_seconds=5.0,
        )

        result = client.execute(probe)

        assert result.status_code == 200
        assert result.response_size == 5
        assert result.response_time_ms >= 0

    finally:
        server.shutdown()
        server.server_close()
