import json

import pytest

from tools.telemetry_sender import (
    generate_events,
    pseudonym,
    read_events,
    run_continuous,
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



def test_invalid_retry_settings():
    with pytest.raises(ValueError, match="max_retries"):
        send_events([], "http://localhost/events", max_retries=-1)
    with pytest.raises(ValueError, match="retry_delay"):
        send_events([], "http://localhost/events", retry_delay=-1)


def test_send_events_retries_temporary_connection_failure(monkeypatch):
    import urllib.error
    import tools.telemetry_sender as sender

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"status": "accepted"}'

    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request)
        if len(calls) == 1:
            raise urllib.error.URLError("temporary connection failure")
        return FakeResponse()

    monkeypatch.setattr(sender.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(sender.time, "sleep", lambda delay: None)

    result = send_events(
        [{"event_id": "test"}],
        "http://localhost/events",
        max_retries=1,
        retry_delay=0,
    )

    assert len(calls) == 2
    assert result == [{"status": "accepted"}]


def test_send_events_does_not_retry_client_http_errors(monkeypatch):
    import io
    import urllib.error
    import tools.telemetry_sender as sender

    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request)
        raise urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", {},
            io.BytesIO(b"Unauthorized")
        )

    monkeypatch.setattr(sender.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="HTTP 401"):
        send_events(
            [{"event_id": "test"}],
            "http://localhost/events",
            max_retries=3,
        )

    assert len(calls) == 1


def test_continuous_mode_stops_cleanly_when_interrupted(monkeypatch):
    import tools.telemetry_sender as sender

    generated = []
    delivered = []

    def fake_generate_events(count, scenario):
        generated.append((count, scenario))
        return [{"event_id": "test"}]

    def fake_send_events(events, endpoint, **kwargs):
        delivered.append((events, endpoint, kwargs))
        return [{"status": "accepted"}]

    def interrupt_sleep(interval):
        raise KeyboardInterrupt

    monkeypatch.setattr(sender, "generate_events", fake_generate_events)
    monkeypatch.setattr(sender, "send_events", fake_send_events)
    monkeypatch.setattr(sender.time, "sleep", interrupt_sleep)

    with pytest.raises(KeyboardInterrupt):
        run_continuous(
            endpoint="http://localhost/events",
            count=10,
            scenario="mixed",
            interval=1,
        )

    assert generated == [(10, "mixed")]
    assert len(delivered) == 1


def test_continuous_mode_rejects_invalid_interval():
    with pytest.raises(ValueError, match="interval"):
        run_continuous(
            endpoint="http://localhost/events",
            interval=0,
        )
