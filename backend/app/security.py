import hmac
import os
import threading
import time

from fastapi import Request
from fastapi.responses import JSONResponse


_rate_lock = threading.Lock()
_rate_buckets = {}


def _enabled(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _positive_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def reset_rate_limit_state() -> None:
    """Reset in-memory counters; primarily useful for tests."""
    with _rate_lock:
        _rate_buckets.clear()


def _rate_limit_response(client_key: str):
    if not _enabled("AEGISAI_RATE_LIMIT_ENABLED", True):
        return None

    limit = _positive_int("AEGISAI_RATE_LIMIT_REQUESTS", 120)
    window = _positive_int("AEGISAI_RATE_LIMIT_WINDOW_SECONDS", 60)
    max_buckets = _positive_int("AEGISAI_RATE_LIMIT_MAX_BUCKETS", 10000)

    now = time.monotonic()
    # One shared API quota per client IP, across every API route.
    bucket_key = client_key

    with _rate_lock:
        bucket = _rate_buckets.get(bucket_key)

        if bucket is None or now - bucket[0] >= window:

            # Reclaim expired entries before allocating a new bucket.
            if bucket is None and len(_rate_buckets) >= max_buckets:
                expired = [
                    key for key, value in _rate_buckets.items()
                    if now - value[0] >= window
                ]

                for key in expired:
                    _rate_buckets.pop(key, None)

                # Never evict active buckets: that could reset a client's
                # rate limit and allow requests to bypass enforcement.
                if len(_rate_buckets) >= max_buckets:
                    return JSONResponse(
                        status_code=503,
                        content={
                            "detail": "Rate limiter capacity reached. Try again later."
                        },
                        headers={"Retry-After": str(window)},
                    )

            _rate_buckets[bucket_key] = (now, 1)
            return None

        started, count = bucket

        if count >= limit:
            retry_after = max(1, int(window - (now - started)))
            return JSONResponse(
                status_code=429,
                content={"detail": "API rate limit exceeded. Try again later."},
                headers={"Retry-After": str(retry_after)},
            )

        _rate_buckets[bucket_key] = (started, count + 1)

    return None


def enforce_api_security(request: Request):
    path = request.url.path

    # Non-API endpoints, including health checks, remain public.
    if not path.startswith("/api/"):
        return None

    client_key = request.client.host if request.client else "unknown"

    # Rate limiting applies to all API routes, including BOLA/BFLA.
    limited = _rate_limit_response(client_key)
    if limited is not None:
        return limited

    # BOLA/BFLA retain their existing X-AegisAI-Auth-Key protection.
    authorization_route = path.startswith("/api/authorization/")

    if authorization_route:
        return None

    # Global API authentication is enabled by default; disable only for local development.
    if not _enabled("AEGISAI_API_AUTH_ENABLED", True):
        return None

    expected_key = os.getenv("AEGISAI_API_KEY", "").strip()
    if not expected_key:
        return JSONResponse(
            status_code=503,
            content={"detail": "API authentication is enabled but AEGISAI_API_KEY is not configured."},
        )

    supplied_key = request.headers.get("X-AegisAI-API-Key", "")
    if not supplied_key or not hmac.compare_digest(supplied_key, expected_key):
        return JSONResponse(
            status_code=401,
            content={"detail": "Missing or invalid API key."},
        )

    return None
