import ipaddress
import os
import socket
from urllib.parse import urlsplit


class AuthorizationTargetPolicy:
    """
    Restricts probes to explicitly allowlisted hosts, ports and IP addresses.

    Environment:
      AEGISAI_AUTH_ALLOWED_HOSTS=127.0.0.1,localhost
      AEGISAI_AUTH_ALLOWED_PORTS=80,443,8000,8080
      AEGISAI_AUTH_ALLOW_LOCAL=true

    Local mode permits loopback addresses only.
    """

    DEFAULT_ALLOWED_PORTS = {80, 443, 8000, 8080}

    def __init__(self) -> None:
        raw_hosts = os.getenv("AEGISAI_AUTH_ALLOWED_HOSTS", "")

        self.allowed_hosts = {
            host.strip().lower().rstrip(".")
            for host in raw_hosts.split(",")
            if host.strip()
        }

        raw_ports = os.getenv("AEGISAI_AUTH_ALLOWED_PORTS", "")

        if raw_ports.strip():
            try:
                self.allowed_ports = {
                    int(port.strip())
                    for port in raw_ports.split(",")
                }
            except ValueError as exc:
                raise ValueError(
                    "AEGISAI_AUTH_ALLOWED_PORTS contains an invalid port."
                ) from exc
        else:
            self.allowed_ports = self.DEFAULT_ALLOWED_PORTS.copy()

        if any(port < 1 or port > 65535 for port in self.allowed_ports):
            raise ValueError("Allowed ports must be between 1 and 65535.")

        self.allow_local = (
            os.getenv("AEGISAI_AUTH_ALLOW_LOCAL", "").lower() == "true"
        )

    def validate(self, url: str) -> list[str]:
        try:
            parsed = urlsplit(url)

            if parsed.scheme not in {"http", "https"}:
                raise ValueError("Only HTTP and HTTPS targets are permitted.")

            if not parsed.hostname:
                raise ValueError("Target URL must contain a hostname.")

            if parsed.username or parsed.password:
                raise ValueError(
                    "Credentials must not be embedded in target URLs."
                )

            if parsed.fragment:
                raise ValueError("URL fragments are not permitted.")

            explicit_port = parsed.port

        except ValueError as exc:
            raise ValueError("Target URL is invalid.") from exc

        hostname = parsed.hostname.lower().rstrip(".")
        port = explicit_port or (443 if parsed.scheme == "https" else 80)

        if hostname not in self.allowed_hosts:
            raise ValueError(
                "Target host is not in the authorization allowlist."
            )

        if port not in self.allowed_ports:
            raise ValueError(
                "Target port is not in the authorization port allowlist."
            )

        try:
            records = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise ValueError(
                "Target hostname could not be resolved."
            ) from exc

        addresses = set()

        for record in records:
            try:
                address = str(ipaddress.ip_address(record[4][0]))
            except (ValueError, IndexError, TypeError) as exc:
                raise ValueError(
                    "DNS returned an invalid target address."
                ) from exc

            addresses.add(address)

        if not addresses:
            raise ValueError("Target hostname resolved to no addresses.")

        validated_addresses = sorted(addresses)

        for address in validated_addresses:
            ip = ipaddress.ip_address(address)

            if self.allow_local:
                if not ip.is_loopback:
                    raise ValueError(
                        "Local testing permits loopback addresses only."
                    )
            elif not ip.is_global:
                raise ValueError(
                    "Target resolves to a non-public address."
                )

        return validated_addresses
