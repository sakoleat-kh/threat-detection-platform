"""Tests for successful SSH login after multiple failures."""

from datetime import datetime, timedelta, timezone
from app.detection.rules.successful_after_failures import (
    SuccessfulAfterFailuresRule,
)
from app.models.normalized_event import NormalizedEvent
from app.detection.engine import DetectionEngine


BASE_TIME = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    source_ip: str,
    timestamp: datetime,
    event_type: str,
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

def make_failures(
    source_ip: str,
    count: int,
    start_time: datetime = BASE_TIME,
) -> list[NormalizedEvent]:
    """Create failed SSH password events."""
    return [
        make_event(
            f"fail-{i}",
            source_ip,
            start_time + timedelta(seconds=i * 30),
            "ssh_failed_password",
        )
        for i in range(count)
    ]

def make_success(
        source_ip: str,
        timestamp: datetime,
) -> NormalizedEvent:
    """Create a successful SSH password event."""
    return make_event(
        "success",
        source_ip,
        timestamp,
        "ssh_accepted_password",
    )

def test_below_threshold_does_not_trigger():
    """Two failures followed by success should not trigger."""

    events = make_failures("10.0.0.1", 2)
    events.append(
        make_success(
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=2),
        )
    )

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_at_threshold_trigger():
    """Three failures followed by success should trigger."""

    events = make_failures("10.0.0.1", 3)
    events.append(
        make_success(
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=2),
        )
    )

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "successful_after_failures"
    assert alerts[0].event.source_ip == "10.0.0.1"

def test_above_threshold_trigger():
    """Four failures followed by success should trigger."""

    events = make_failures("10.0.0.1", 4)
    events.append(
        make_success(
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=3),
        )
    )
    alerts = SuccessfulAfterFailuresRule().evaluate(events)
    assert len(alerts) == 1

def test_success_outside_window_does_not_trigger():
    """Success outside the five-minute window should not trigger."""

    events = make_failures("10.0.0.1", 3)
    events.append(
        make_success(
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=10),
        )
    )

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_multi_ip_isolation():
    """Failures from different IPs must not be combined."""

    events = [
        *make_failures("10.0.0.1", 2),
        *make_failures("10.0.0.2", 2),
        make_success(
            "10.0.0.2",
            BASE_TIME + timedelta(minutes=2),
        )
    ]

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_success_without_failures_does_not_trigger():
    """A successful login without preceding failures should not trigger."""

    events = [
        make_success(
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=1),
        )
    ]

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_mixed_event_types_are_ignored():
    """Unrelated event types should not count as SSH failures."""

    events = [
        make_event(
            "1",
            "10.0.0.1",
            BASE_TIME,
            "ssh_failed_password",
        ),
        make_event(
            "2",
            "10.0.0.1",
            BASE_TIME + timedelta(seconds=30),
            "sudo_command",
        ),
        make_event(
            "3",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=1),
            "ssh_failed_password",
        ),
        make_event(
            "4",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=1, seconds=30),
            "access",
        ),
        make_success(
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=2),
        ),
    ]

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_success_before_failures_does_not_trigger():
    """a success occurring before failures should not trigger."""

    events = [
        make_success(
            "10.0.0.1",
            BASE_TIME,
        ),
        *make_failures(
            "10.0.0.1",
            3,
            BASE_TIME + timedelta(minutes=1),
        ),
    ]

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_engine_runs_successful_after_failures_rule():
    """detectionEngine should execute Rule 2."""

    events = make_failures("10.0.0.5", 3)
    events.append(
        make_success(
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=2),
        )
    )

    engine = DetectionEngine()
    engine.register_rule(SuccessfulAfterFailuresRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "successful_after_failures"
    assert alerts[0].event.event_id == "success"