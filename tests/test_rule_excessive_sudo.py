"""Comprehensive tests for Rule 3."""

from datetime import datetime, timedelta, timezone

from app.detection.rules.excessive_sudo import ExcessiveSudoRule
from app.models.normalized_event import NormalizedEvent

BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    username: str,
    timestamp: datetime,
    event_type: str
) -> NormalizedEvent:
    """Create a normalized auth event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="auth",
        source_ip=None,
        username=username,
        raw_event_type=event_type,
        raw_data={},
    )

def make_commands(
    username: str,
    count: int,
    start_time: datetime = BASE_TIME,
) -> list[NormalizedEvent]:
    """Create sudo command events."""
    return [
        make_event(
            f"comand-{username}-{i}",
            username,
            start_time + timedelta(seconds=i * 20),
            "sudo_command",
        )
        for i in range(count)
    ]

def make_failures(
    username: str,
    count: int,
    start_time: datetime = BASE_TIME,
) -> list[NormalizedEvent]:
    """Create sudo authentication failure events."""
    return [
        make_event(
            f"failure-{username}-{i}",
            username,
            start_time + timedelta(seconds=i * 30),
            "sudo_auth_failed",
        )
        for i in range(count)
    ]

def test_below_comamnd_threshold_does_not_trigger():
    """Nine sudo commands should not trigger."""

    events = make_commands("ubuntu", 9)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_above_command_threshold_trigger():
    """Ten sudo commands should trigger."""

    events = make_commands("ubuntu", 10)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "excessive_sudo"
    assert alerts[0].event.username == "ubuntu"

def test_auth_failure_threshold_triggers():
    """Three sudo authentication failures should trigger."""

    events = make_failures("ubuntu", 3)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "excessive_sudo"
    assert alerts[0].event.username == "ubuntu"

def test_below_auth_failure_threshold_does_not_trigger():
    """Two sudo authentication failures should not trigger."""

    events = make_failures("ubuntu", 2)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_excessive_and_normal_users_are_isolated():
    """An excessive user should alert without affecting a normal user."""

    events = [
        *make_commands("ubuntu", 10),
        *make_commands("admin", 5)
    ]

    alerts = ExcessiveSudoRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.username == "ubuntu"

def test_different_users_below_threshold_do_not_combine():
    """Sudo commands from different users must not be combined."""

    events = [
        *make_commands("ubuntu", 9),
        *make_commands("admin", 9)
    ]

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_command_and_failure_counts_are_separete():
    """Commands and failures must not combine into one threshold."""

    events = [
        *make_commands("ubuntu", 9),
        make_failures("ubuntu", 2)[0],
    ]

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []