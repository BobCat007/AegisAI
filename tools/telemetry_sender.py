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
    max_retries: int = 0,
    retry_delay: float = 1.0,
) -> list[dict]:
    if not endpoint.startswith(("http://", "https://")):
        raise ValueError("Endpoint must use HTTP or HTTPS")

    if not 1 <= batch_size <= 500:
        raise ValueError("batch_size must be between 1 and 500")

    if max_retries < 0:
        raise ValueError("max_retries cannot be negative")

    if retry_delay < 0:
        raise ValueError("retry_delay cannot be negative")

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

        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    result = json.loads(response.read().decode())
                    responses.append(result)
                    print(json.dumps(result, indent=2))
                    break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")
                retryable = exc.code in (408, 429) or exc.code >= 500
                if not retryable or attempt >= max_retries:
                    raise RuntimeError(
                        f"Server returned HTTP {exc.code}: {detail}"
                    ) from exc
                error_message = f"HTTP {exc.code}: {detail}"
            except urllib.error.URLError as exc:
                if attempt >= max_retries:
                    raise RuntimeError(
                        f"Could not reach AegisAI after {attempt + 1} "
                        f"attempt(s): {exc}"
                    ) from exc
                error_message = str(exc)

            attempt += 1
            delay = retry_delay * (2 ** (attempt - 1))
            print(
                f"Delivery attempt {attempt}/{max_retries} failed: "
                f"{error_message}. Retrying in {delay:.1f}s...",
                file=sys.stderr,
            )
            time.sleep(delay)

    return responses


def run_continuous(
    endpoint: str,
    count: int = 100,
    scenario: str = "normal",
    interval: float = 5.0,
    batch_size: int = 100,
    api_key: str | None = None,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> None:
    """Generate and deliver telemetry batches until interrupted."""
    if interval <= 0:
        raise ValueError("interval must be greater than zero")
    if max_retries < 0:
        raise ValueError("max_retries cannot be negative")
    if retry_delay < 0:
        raise ValueError("retry_delay cannot be negative")

    cycle = 0
    print(
        f"Starting continuous telemetry: scenario={scenario}, "
        f"events_per_cycle={count}, interval={interval}s, endpoint={endpoint}"
    )
    print("Press Ctrl+C to stop.")

    while True:
        cycle += 1
        events = generate_events(count, scenario)
        print(f"\nCycle {cycle}: generated {len(events)} events.")

        send_events(
            events,
            endpoint,
            api_key=api_key,
            batch_size=batch_size,
            max_retries=max_retries,
            retry_delay=retry_delay,
        )

        print(
            f"Cycle {cycle} delivered successfully. "
            f"Waiting {interval}s for the next batch."
        )
        time.sleep(interval)


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

    continuous = subparsers.add_parser(
        "continuous",
        help="Generate and send telemetry batches continuously",
    )
    continuous.add_argument(
        "--url",
        default="http://127.0.0.1:8000/api/telemetry/events",
    )
    continuous.add_argument("--count", type=int, default=100)
    continuous.add_argument(
        "--scenario",
        choices=["normal", "suspicious", "mixed"],
        default="normal",
    )
    continuous.add_argument("--interval", type=float, default=5.0)
    continuous.add_argument("--batch-size", type=int, default=100)
    continuous.add_argument("--max-retries", type=int, default=3)
    continuous.add_argument("--retry-delay", type=float, default=1.0)

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

        elif args.command == "continuous":
            run_continuous(
                endpoint=args.url,
                count=args.count,
                scenario=args.scenario,
                interval=args.interval,
                batch_size=args.batch_size,
                api_key=os.getenv("AEGISAI_API_KEY"),
                max_retries=args.max_retries,
                retry_delay=args.retry_delay,
            )

    except KeyboardInterrupt:
        print("\nContinuous telemetry stopped by user.")
        return 0
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
