"""Tests for excessive sudo detection."""

from datetime import datetime, timedelta, timezone

from app.detection.rules.excessive_sudo import ExcessiveSudoRule
from app.models.normalized_event import NormalizedEvent
from app.detection.engine import DetectionEngine

BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    username: str,
    timestamp: datetime,
    event_type: str,
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

def make_sudo_commands(
    username: str,
    count: int,
    start_time: datetime = BASE_TIME,
) -> list[NormalizedEvent]:
    """Create sudo command events."""
    return [
        make_event(
            f"command-{i}",
            username,
            start_time + timedelta(seconds=i * 20),
            "sudo_command",
        )
        for i in range(count)
    ]


def make_sudo_failures(
    username: str,
    count: int,
    start_time: datetime = BASE_TIME,
) -> list[NormalizedEvent]:
    """Create sudo authetication failre events."""
    return [
        make_event(
            f"failure-{i}",
            username,
            start_time + timedelta(seconds=i * 30),
            "sudo_auth_failed",
        )
        for i in range(count)
    ]

def test_nine_sudo_commands_do_not_trigger():
    """Nine sudo commands should stay below the threshold."""

    events = make_sudo_commands("ubuntu", 9)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []


def test_ten_sudo_command_trigger():
    """Ten sudo commands within five minutes should trigger."""

    events = make_sudo_commands("ubuntu", 10)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "excessive_sudo"
    assert alerts[0].event.username == "ubuntu"

def test_three_sudo_failures_trigger():
    """Three sudo authetication failures should trigger."""

    events = make_sudo_failures("ubuntu", 3)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "excessive_sudo"

def test_two_sudo_failures_do_not_trigger():
    """Two sudo authentication failures should not trigger."""

    events = make_sudo_failures("ubuntu", 2)

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_sudo_commands_apread_over_window_do_not_trigger():
    """Ten sudo commands spread beyong five minutes should not trigger."""

    events = [
        make_event(
            str(i),
            "ubuntu",
            BASE_TIME + timedelta(minutes=i),
            "sudo_command",
        )
        for i in range(10)
    ]

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_sudo_failures_spread_over_window_do_not_trigger():
    """Three sudo failures spread beyond five minutes should not trigger."""

    events = [
        make_event(
            str(i),
            "ubuntu",
            BASE_TIME + timedelta(minutes=i * 3),
            "sudo_auth_failed",
        )
        for i in range(3)
    ]

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_different_users_are_isolated():
    """Sudo activity from different users must not be combined."""

    events = [
        *make_sudo_commands("ubuntu", 5),
        *make_sudo_commands("admin", 5),
    ]

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_sudo_event_types_are_counted_separately():
    """Commands and authentication failures must not be combined."""

    events = [
        *make_sudo_commands("ubuntu", 8),
        *make_sudo_failures("ubuntu", 2),
    ]

    alerts = ExcessiveSudoRule().evaluate(events)

    assert alerts == []

def test_engine_runs_excessive_sudo_rule():
    """DetectionEngine should execute Rule 3."""

    events = make_sudo_commands("ubuntu", 10)

    engine = DetectionEngine()
    engine.register_rule(ExcessiveSudoRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "excessive_sudo"
    assert alerts[0].event.username == "ubuntu"

def test_sudo_event_without_username_or_source_ip_is_skipped():
    """Sudo events without an identifiable source should be ignored."""

    event = make_event(
        "missing-source",
        None,
        BASE_TIME,
        "sudo_command",
    )

    alerts = ExcessiveSudoRule().evaluate([event])

    assert alerts == []