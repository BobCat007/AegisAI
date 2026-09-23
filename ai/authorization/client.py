import time
import urllib.error
import urllib.parse
import urllib.request

from ai.authorization.models import AuthorizationProbe, AuthorizationProbeResult


class AuthorizationProbeClient:
    """
    Executes controlled HTTP authorization probes.
    """

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds

    def execute(self, probe: AuthorizationProbe) -> AuthorizationProbeResult:
        start = time.perf_counter()

        url = probe.url

        if probe.query_params:
            query = urllib.parse.urlencode(probe.query_params)
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{query}"

        body = None

        if probe.body is not None:
            import json

            body = json.dumps(probe.body).encode("utf-8")

        request = urllib.request.Request(
            url=url,
            data=body,
            headers=probe.headers,
            method=probe.method.upper(),
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                response_body = response.read()
                status_code = response.status
                response_size = len(response_body)

        except urllib.error.HTTPError as error:
            response_body = error.read()
            status_code = error.code
            response_size = len(response_body)

        elapsed_ms = (time.perf_counter() - start) * 1000

        return AuthorizationProbeResult(
            status_code=status_code,
            response_time_ms=elapsed_ms,
            response_size=response_size,
        )
