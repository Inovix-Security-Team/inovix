import psutil

from security_engine.collectors import (
    NetworkCollector,
    ProcessCollector,
    SystemCollector,
)


def test_system_collector_returns_valid_event():
    event = SystemCollector().collect()

    assert event.event_type == "system"
    assert event.source == "system_monitor"
    assert isinstance(event.timestamp, str)
    assert isinstance(event.data, dict)

    assert isinstance(event.data["cpu_percent"], (int, float))
    assert isinstance(event.data["memory_percent"], (int, float))
    assert isinstance(event.data["disk_percent"], (int, float))
    assert "uptime_seconds" in event.data
    assert "hostname" in event.data
    assert "os" in event.data


def test_process_collector_returns_events():
    events = ProcessCollector().collect()

    assert isinstance(events, list)

    for event in events:
        assert event.event_type == "process"
        assert event.source == "process_monitor"
        assert isinstance(event.timestamp, str)
        assert isinstance(event.data, dict)

        assert isinstance(event.data["pid"], int)
        assert event.data["pid"] >= 0
        assert event.data["name"]


def test_network_collector_returns_events():
    events = NetworkCollector().collect()

    assert isinstance(events, list)

    for event in events:
        assert event.event_type == "network"
        assert event.source == "network_monitor"
        assert isinstance(event.timestamp, str)
        assert isinstance(event.data, dict)

        assert "local_address" in event.data
        assert "remote_address" in event.data
        assert "status" in event.data
        assert "pid" in event.data


def test_all_collector_events_have_standard_format():
    collectors = [
        SystemCollector(),
        ProcessCollector(),
        NetworkCollector(),
    ]

    for collector in collectors:
        result = collector.collect()

        events = result if isinstance(result, list) else [result]

        for event in events:
            data = event.to_dict()

            assert "event_type" in data
            assert "source" in data
            assert "timestamp" in data
            assert "data" in data


def test_process_collector_handles_access_denied(monkeypatch):
    def raise_access_denied(*args, **kwargs):
        raise psutil.AccessDenied()

    monkeypatch.setattr(
        psutil,
        "process_iter",
        raise_access_denied,
    )

    events = ProcessCollector().collect()

    assert events == []


def test_network_collector_handles_access_denied(monkeypatch):
    def raise_access_denied(*args, **kwargs):
        raise psutil.AccessDenied()

    monkeypatch.setattr(
        psutil,
        "net_connections",
        raise_access_denied,
    )

    events = NetworkCollector().collect()

    assert events == []


def test_network_collector_handles_no_connections(monkeypatch):
    monkeypatch.setattr(
        psutil,
        "net_connections",
        lambda kind: [],
    )

    events = NetworkCollector().collect()

    assert events == []