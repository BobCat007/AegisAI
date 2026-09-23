from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from ai.authorization.client import AuthorizationProbeClient
from ai.authorization.models import AuthorizationProbe


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}'

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/json",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


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
        )

        client = AuthorizationProbeClient()

        result = client.execute(probe)

        assert result.status_code == 200
        assert result.response_time_ms >= 0
        assert result.response_size == len(
            b'{"status":"ok"}'
        )
    finally:
        server.shutdown()
        server.server_close()
