"""Comprehensive tests for the SSH brute-force detection rule."""

from datetime import datetime, timedelta, timezone

from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.models.normalized_event import NormalizedEvent

BASE_TIME = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    source_ip: str,
    timestamp: datetime,
    event_type: str = "ssh_failed_password",
) -> NormalizedEvent:
    """create a normalized event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="auth",
        source_ip=source_ip,
        username="ubuntu",
        raw_event_type=event_type,
        raw_data={},
    )

def test_below_threshold():
    """Four failures should not trigger an alert."""

    events = [
        make_event(
            str(i),
            "10.0.0.1",
            BASE_TIME + timedelta(seconds=i * 30),
        )
        for i in range(4)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert alerts == []

def test_at_threshold():
    """Five failures within the window should trigger."""

    events = [
        make_event(
            str(i),
            "10.0.0.1",
            BASE_TIME + timedelta(seconds=i * 30),
        )
        for i in range(5)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.source_ip == "10.0.0.1"

def test_above_threshold():
    """More than five failures within the window should trigger."""

    events = [
        make_event(
            str(i),
            "10.0.0.1",
            BASE_TIME + timedelta(seconds=i * 30),
        )
        for i in range(6)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.source_ip == "10.0.0.1"

def test_spread_over_time_does_not_trigger():
    """Failures spread over two hours should not trigger."""

    events = [
        make_event(
            str(i),
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=i * 30),
        )
        for i in range(5)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert alerts == []

def test_multi_ip_isolation():
    """Failures from different IPs must be counted independently."""

    events = [
        *[
            make_event(
                f"a{i}",
                "10.0.0.1",
                BASE_TIME + timedelta(seconds=i * 30),
            )
            for i in range(3)
        ],
        *[
            make_event(
                f"b{i}",
                "10.0.0.2",
                BASE_TIME + timedelta(seconds=i * 30),
            )
            for i in range(5)
        ],
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.source_ip == "10.0.0.2"

def test_mixed_event_types():
    """Only failed SSH password events should count."""

    events = [
        make_event(
            "1",
            "10.0.0.1",
            BASE_TIME,
        ),
        make_event(
            "2",
            "10.0.0.1",
            BASE_TIME + timedelta(seconds=30),
            "ssh_success",
        ),
        make_event(
            "3",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=1),
        ),
        make_event(
            "4",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=1, seconds=30),
            "sudo_command",
        ),
        make_event(
            "5",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=2),
        ),
        make_event(
            "6",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=2, seconds=30),
            "access",
        ),
        make_event(
            "7",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=3),
        ),
        make_event(
            "8",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=3, seconds=30)
        )
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.source_ip == "10.0.0.1"

def test_exact_window_boundary():
    """Five failures exactly within five minutes should trigger."""

    timestamps = [
        BASE_TIME,
        BASE_TIME + timedelta(minutes=1),
        BASE_TIME + timedelta(minutes=2),
        BASE_TIME + timedelta(minutes=3),
        BASE_TIME + timedelta(minutes=5),
    ]

    events = [
        make_event(str(i), "10.0.0.1", timestamp)
        for i, timestamp in enumerate(timestamps)
    ]
    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1