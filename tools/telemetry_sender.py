"""Privacy-conscious AegisAI telemetry sender and traffic simulator."""

import argparse
import hashlib
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def pseudonym(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def generate_events(count: int = 100, scenario: str = "normal") -> list[dict]:
    if count < 1:
        raise ValueError("count must be positive")

    if scenario not in {"normal", "suspicious", "mixed"}:
        raise ValueError("Unsupported scenario")

    events = []
    now = datetime.now(timezone.utc).isoformat()

    for index in range(count):
        suspicious = (
            scenario == "suspicious"
            or (scenario == "mixed" and index % 3 == 0)
        )

        if suspicious:
            path = "/api/auth/login"
            method = "POST"
            status = random.choices([200, 401, 403], [10, 75, 15])[0]
            latency = random.uniform(5, 80)
            identity = f"identity-{index % 2}"
            client = f"client-{index % 20}"
        else:
            path = random.choice([
                "/api/users",
                "/api/products",
                "/api/orders",
            ])
            method = random.choice(["GET", "GET", "POST"])
            status = random.choices([200, 201, 400], [90, 8, 2])[0]
            latency = random.uniform(20, 180)
            identity = f"identity-{index % 40}"
            client = f"client-{index % 15}"

        events.append({
            "event_id": str(uuid4()),
            "timestamp": now,
            "method": method,
            "endpoint_path": path,
            "status_code": status,
            "latency_ms": round(latency, 2),
            "response_size_bytes": random.randint(100, 5000),
            "identity_hash": pseudonym(identity),
            "client_hash": pseudonym(client),
        })

    return events


def write_events(events: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")


def read_events(source: Path) -> list[dict]:
    events = []
    with source.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}"
                ) from exc
    return events


def send_events(
    events: list[dict],
    endpoint: str,
    api_key: str | None = None,
    batch_size: int = 100,
) -> list[dict]:
    if not endpoint.startswith(("http://", "https://")):
        raise ValueError("Endpoint must use HTTP or HTTPS")

    if not 1 <= batch_size <= 500:
        raise ValueError("batch_size must be between 1 and 500")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-AegisAI-API-Key"] = api_key

    responses = []

    for start in range(0, len(events), batch_size):
        batch = events[start:start + batch_size]
        body = json.dumps({"events": batch}).encode()

        request = urllib.request.Request(
            endpoint,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode())
                responses.append(result)
                print(json.dumps(result, indent=2))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"Server returned HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Could not reach AegisAI: {exc}") from exc

    return responses


def main():
    parser = argparse.ArgumentParser(
        description="AegisAI external telemetry sender"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    simulate = subparsers.add_parser("simulate")
    simulate.add_argument("--count", type=int, default=100)
    simulate.add_argument(
        "--scenario",
        choices=["normal", "suspicious", "mixed"],
        default="normal",
    )
    simulate.add_argument(
        "--output",
        type=Path,
        default=Path("data/telemetry/demo_events.jsonl"),
    )

    send = subparsers.add_parser("send")
    send.add_argument(
        "--input",
        type=Path,
        default=Path("data/telemetry/demo_events.jsonl"),
    )
    send.add_argument(
        "--url",
        default="http://127.0.0.1:8000/api/telemetry/events",
    )
    send.add_argument("--batch-size", type=int, default=100)

    args = parser.parse_args()

    try:
        if args.command == "simulate":
            events = generate_events(args.count, args.scenario)
            write_events(events, args.output)
            print(
                f"Generated {len(events)} {args.scenario} events: "
                f"{args.output}"
            )

        elif args.command == "send":
            events = read_events(args.input)
            if not events:
                raise ValueError("Input file contains no events")

            send_events(
                events,
                args.url,
                os.getenv("AEGISAI_API_KEY"),
                args.batch_size,
            )

    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
