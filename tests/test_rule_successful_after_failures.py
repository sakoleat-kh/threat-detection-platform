"""Comprehensive tests for Rule 2."""

from datetime import datetime, timedelta, timezone

from app.detection.rules.successful_after_failures import (
    SuccessfulAfterFailuresRule,
)
from app.models.normalized_event import NormalizedEvent

BASE_TIME = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)

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

def test_failures_then_success_within_window():
    """Three failures followed by success within five minutes should alert."""

    events = [
        make_event(
            f"fail-{i}",
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=i),
            "ssh_failed_password",
        )
        for i in range(3)
    ]

    events.append(
        make_event(
            "success",
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=3),
            "ssh_accepted_password",
        )
    )

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "successful_after_failures"
    assert alerts[0].event.event_id == "success"

def test_success_with_no_prior_failures():
    """A normal successful login should not alert."""

    events = [
        make_event(
            "success",
            "10.0.0.5",
            BASE_TIME,
            "ssh_accepted_password",
        )
    ]

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_failures_then_success_too_far_apart():
    """Success outside the five-minute window should not alert."""

    events = [
        make_event(
            f"fail-{i}",
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=i),
            "ssh_failed_password",
        )
        for i in range(3)
    ]

    events.append(
        make_event(
            "success",
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=10),
            "ssh_accepted_password",
        )
    )

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []

def test_different_ips_are_isolated():
    """Failures from different IPs must not be combined."""

    events = [
        make_event(
            "a1",
            "10.0.0.1",
            BASE_TIME,
            "ssh_failed_password",
        ),
        make_event(
            "a2",
            "10.0.0.1",
            BASE_TIME + timedelta(minutes=1),
            "ssh_failed_password",
        ),
        make_event(
            "b1",
            "10.0.0.2",
            BASE_TIME,
            "ssh_failed_password",
        ),
        make_event(
            "b2",
            "10.0.0.2",
            BASE_TIME + timedelta(minutes=1),
            "ssh_failed_password",
        ),
        make_event(
            "b3",
            "10.0.0.2",
            BASE_TIME + timedelta(minutes=2),
            "ssh_failed_password",
        ),
        make_event(
            "success",
            "10.0.0.2",
            BASE_TIME + timedelta(minutes=3),
            "ssh_accepted_password",
        ),
    ]

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.source_ip == "10.0.0.2"

def test_old_failures_are_removed_from_window():
    """Failures outside the five-minute window should be discarded."""

    events = [
        make_event(
            "fail-1",
            "10.0.0.5",
            BASE_TIME,
            "ssh_failed_password",
        ),
        make_event(
            "fail-2",
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=3),
            "ssh_failed_password",
        ),
        make_event(
            "fail-3",
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=6),
            "ssh_failed_password",
        ),
        make_event(
            "success",
            "10.0.0.5",
            BASE_TIME + timedelta(minutes=7),
            "ssh_accepted_password",
        ),
    ]

    alerts = SuccessfulAfterFailuresRule().evaluate(events)

    assert alerts == []