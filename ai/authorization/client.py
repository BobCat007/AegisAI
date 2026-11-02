import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse

from ai.authorization.models import AuthorizationProbe, AuthorizationProbeResult


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, port, pinned_ip, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port),
            self.timeout,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, port, pinned_ip, timeout, context):
        super().__init__(
            hostname,
            port,
            timeout=timeout,
            context=context,
        )
        self.pinned_ip = pinned_ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.pinned_ip, self.port),
            self.timeout,
        )

        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except Exception:
            raw_socket.close()
            raise


class AuthorizationProbeClient:
    """
    Executes HTTP probes against validated, pinned IP addresses.

    HTTPS retains certificate verification and hostname validation.
    Redirects are not followed. Response data is bounded and fingerprinted.
    """

    FORBIDDEN_HEADERS = {
        "host",
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "content-length",
        "transfer-encoding",
    }

    ALLOWED_METHODS = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    }

    HEADER_NAME_PATTERN = re.compile(
        r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"
    )

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 1024 * 1024,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")

        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive.")

        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.ssl_context = ssl_context or ssl.create_default_context()

    @staticmethod
    def _fingerprint(response_body: bytes) -> str:
        return hashlib.sha256(response_body).hexdigest()

    def _validate_headers(self, supplied_headers: dict) -> dict:
        if not isinstance(supplied_headers, dict):
            raise ValueError("Request headers must be a dictionary.")

        validated = {}

        for name, value in supplied_headers.items():
            if not isinstance(name, str) or not self.HEADER_NAME_PATTERN.fullmatch(name):
                raise ValueError("Invalid HTTP header name.")

            if not isinstance(value, str):
                raise ValueError("HTTP header values must be strings.")

            if "\r" in value or "\n" in value:
                raise ValueError("HTTP header values cannot contain CR or LF.")

            normalized_name = name.lower()

            if normalized_name in self.FORBIDDEN_HEADERS:
                raise ValueError(
                    f"The {name} header cannot be overridden."
                )

            validated[normalized_name] = (name, value)

        return {
            original_name: value
            for original_name, value in validated.values()
        }

    def execute(
        self,
        probe: AuthorizationProbe,
        resolved_addresses: list[str],
    ) -> AuthorizationProbeResult:

        if not resolved_addresses:
            raise ValueError("No validated target addresses were supplied.")

        parsed = urllib.parse.urlsplit(probe.url)

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Invalid HTTP probe URL.")

        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Invalid target URL.")

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid target port.") from exc

        method = probe.method.upper()

        if method not in self.ALLOWED_METHODS:
            raise ValueError("Unsupported authorization probe method.")

        hostname = parsed.hostname
        port = port or (443 if parsed.scheme == "https" else 80)

        addresses = []

        for address in resolved_addresses:
            try:
                addresses.append(str(ipaddress.ip_address(address)))
            except ValueError as exc:
                raise ValueError("Invalid validated target IP address.") from exc

        headers = self._validate_headers(probe.headers)

        path = parsed.path or "/"
        query_parts = [parsed.query] if parsed.query else []

        if probe.query_params:
            query_parts.append(
                urllib.parse.urlencode(probe.query_params)
            )

        if query_parts:
            path += "?" + "&".join(query_parts)

        default_port = 443 if parsed.scheme == "https" else 80

        if ":" in hostname:
            host_header = f"[{hostname}]"
        else:
            host_header = hostname

        if port != default_port:
            host_header = f"{host_header}:{port}"

        headers["Host"] = host_header

        body = None

        if probe.body is not None:
            body = json.dumps(probe.body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")

        start = time.perf_counter()
        last_error = None

        for address in addresses:
            connection = None

            try:
                if parsed.scheme == "https":
                    connection = _PinnedHTTPSConnection(
                        hostname,
                        port,
                        address,
                        self.timeout_seconds,
                        self.ssl_context,
                    )
                else:
                    connection = _PinnedHTTPConnection(
                        hostname,
                        port,
                        address,
                        self.timeout_seconds,
                    )

                connection.request(
                    method,
                    path,
                    body=body,
                    headers=headers,
                )

                response = connection.getresponse()
                response_body = response.read(self.max_response_bytes + 1)

                truncated = len(response_body) > self.max_response_bytes

                if truncated:
                    response_body = response_body[:self.max_response_bytes]

                elapsed_ms = (time.perf_counter() - start) * 1000

                return AuthorizationProbeResult(
                    status_code=response.status,
                    response_time_ms=elapsed_ms,
                    response_size=len(response_body),
                    response_fingerprint=self._fingerprint(response_body),
                    response_truncated=truncated,
                )

            except ssl.SSLCertVerificationError:
                raise

            except TimeoutError:
                raise

            except ssl.SSLError:
                raise

            except (OSError, http.client.HTTPException) as exc:
                last_error = exc

            finally:
                if connection is not None:
                    connection.close()

        raise ConnectionError(
            "Authorization probe could not connect to any validated address."
        ) from last_error
