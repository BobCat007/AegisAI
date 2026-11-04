import json

import pytest

from tools.telemetry_sender import (
    generate_events,
    pseudonym,
    read_events,
    send_events,
    write_events,
)


def test_generate_normal_events():
    events = generate_events(25, "normal")
    assert len(events) == 25
    assert all(event["status_code"] in (200, 201, 400) for event in events)


def test_generate_suspicious_events():
    events = generate_events(25, "suspicious")
    assert all(event["endpoint_path"] == "/api/auth/login" for event in events)
    assert sum(event["status_code"] in (401, 403) for event in events) > 0


def test_generate_mixed_events():
    events = generate_events(30, "mixed")
    assert any(event["endpoint_path"] == "/api/auth/login" for event in events)
    assert any(event["endpoint_path"] == "/api/users" for event in events)


def test_invalid_scenario():
    with pytest.raises(ValueError):
        generate_events(10, "invalid")


def test_invalid_count():
    with pytest.raises(ValueError):
        generate_events(0)


def test_pseudonym_is_deterministic():
    assert pseudonym("identity-1") == pseudonym("identity-1")
    assert pseudonym("identity-1") != pseudonym("identity-2")


def test_write_and_read_jsonl(tmp_path):
    events = generate_events(5)
    output = tmp_path / "events.jsonl"
    write_events(events, output)
    assert read_events(output) == events


def test_invalid_jsonl_line(tmp_path):
    output = tmp_path / "bad.jsonl"
    output.write_text("{invalid}\n")
    with pytest.raises(ValueError, match="line 1"):
        read_events(output)


def test_invalid_endpoint():
    with pytest.raises(ValueError):
        send_events([], "ftp://localhost/events")


def test_invalid_batch_size():
    with pytest.raises(ValueError):
        send_events([], "http://localhost/events", batch_size=501)
