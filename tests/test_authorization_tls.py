import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
import trustme

from ai.authorization.client import AuthorizationProbeClient
from ai.authorization.models import (
    AuthorizationProbe,
    AuthorizationTestContext,
)


class TLSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"tls-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def tls_server(tmp_path):
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")

    cert_file = tmp_path / "server.crt"
    key_file = tmp_path / "server.key"
    ca_file = tmp_path / "ca.crt"

    server_cert.cert_chain_pems[0].write_to_path(cert_file)
    server_cert.private_key_pem.write_to_path(key_file)
    ca.cert_pem.write_to_path(ca_file)

    server = ThreadingHTTPServer(("127.0.0.1", 0), TLSHandler)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(
        certfile=str(cert_file),
        keyfile=str(key_file),
    )

    server.socket = server_context.wrap_socket(
        server.socket,
        server_side=True,
    )

    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    _, port = server.server_address

    try:
        yield {
            "url": f"https://localhost:{port}/health",
            "ip_url": f"https://127.0.0.1:{port}/health",
            "ca_file": ca_file,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def make_probe(url):
    return AuthorizationProbe(
        method="GET",
        url=url,
        context=AuthorizationTestContext(
            identity="tls-test-user",
            authenticated=True,
        ),
        expected_outcome="allow",
    )


def test_https_accepts_trusted_certificate_and_correct_hostname(tls_server):
    context = ssl.create_default_context(cafile=str(tls_server["ca_file"]))
    client = AuthorizationProbeClient(timeout_seconds=5, ssl_context=context)

    result = client.execute(
        make_probe(tls_server["url"]),
        resolved_addresses=["127.0.0.1"],
    )

    assert result.status_code == 200
    assert result.response_fingerprint is not None
    assert result.response_truncated is False


def test_https_rejects_untrusted_certificate(tls_server):
    client = AuthorizationProbeClient(timeout_seconds=5)

    with pytest.raises(ssl.SSLCertVerificationError):
        client.execute(
            make_probe(tls_server["url"]),
            resolved_addresses=["127.0.0.1"],
        )


def test_https_rejects_hostname_mismatch(tls_server):
    context = ssl.create_default_context(cafile=str(tls_server["ca_file"]))
    client = AuthorizationProbeClient(timeout_seconds=5, ssl_context=context)

    with pytest.raises(ssl.SSLCertVerificationError):
        client.execute(
            make_probe(tls_server["ip_url"]),
            resolved_addresses=["127.0.0.1"],
        )
