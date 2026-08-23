"""Tests for SSH brute-force detection."""

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
    """Create a normalized event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="auth",
        source_ip=source_ip,
        username="ubuntu",
        raw_event_type=event_type,
        raw_data={},
    )

def test_spread_over_two_hours_does_not_trigger():
    """Five failed failures spread over two hours should not trigger."""

    events = [
        make_event(str(i), "10.0.0.5", BASE_TIME + timedelta(minutes=i * 30))
        for i in range(5)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert alerts == []

def test_clustered_failures_within_three_minutes_trigger():
    """Five failures within three minutes should trigger."""

    events = [
        make_event(
            str(i),
            "10.0.0.5",
            BASE_TIME + timedelta(seconds=i * 45),
        )
        for i in range(5)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "ssh_brute_force"
    assert alerts[0].event.source_ip == "10.0.0.5"

def test_exact_five_minute_boundary_triggers():
    """Five failures exactly five minutes apart should trigger."""

    timestamps = [
        BASE_TIME,
        BASE_TIME + timedelta(minutes=1),
        BASE_TIME + timedelta(minutes=2),
        BASE_TIME + timedelta(minutes=3),
        BASE_TIME + timedelta(minutes=5),
    ]

    events = [
        make_event(str(i), "10.0.0.5", timestamp)
        for i, timestamp in enumerate(timestamps)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1

def test_more_than_five_minutes_does_not_trigger():
    """Five failures apanning more than five minutes should not trigger."""

    timestamps = [
        BASE_TIME,
        BASE_TIME + timedelta(minutes=1),
        BASE_TIME + timedelta(minutes=2),
        BASE_TIME + timedelta(minutes=3),
        BASE_TIME + timedelta(minutes=5, seconds=1),
    ]

    events = [
        make_event(str(i), "10.0.0.5", timestamp)
        for i, timestamp in enumerate(timestamps)
    ]


    alerts = SSHBruteForceRule().evaluate(events)
    assert alerts == []