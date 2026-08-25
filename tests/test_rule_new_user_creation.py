"""Dedicated tests for Rule 4: new user creation."""

from datetime import datetime, timezone

from app.detection.rules.new_user_creation import NewUserCreationRule
from app.models.normalized_event import NormalizedEvent

def make_event(
    event_id: str,
    username: str,
    uid: int,
    event_type: str = "user_added",
) -> NormalizedEvent:
    """Create a normalized event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source_type="auth",
        source_ip=None,
        username=username,
        raw_event_type=event_type,
        raw_data={"uid": uid},
    )

def test_single_user_added_event_creates_alert():
    """One USER_ADDED event should create one alerts."""

    events = [
        make_event("1", "alice", 1001),
    ]

    alerts = NewUserCreationRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "new_user_creation"
    assert alerts[0].event.event_id == "1"
    assert alerts[0].event.username == "alice"

def test_multiple_user_added_events_create_multiple_alerts():
    """Every USER_ADDED event should create its own alert."""

    events = [
        make_event("1", "alice", 1001),
        make_event("2", "bob", 1002),
        make_event("3", "carol", 2000),
    ]

    alerts = NewUserCreationRule().evaluate(events)

    assert len(alerts) == 3
    assert [alert.event.username for alert in alerts] == [
        "alice",
        "bob",
        "carol",
    ]

def test_no_events_returns_no_alerts():
    """An empty event list should return no alerts."""

    alerts = NewUserCreationRule().evaluate([])

    assert alerts == []

def test_system_and_human_uids_both_create_alerts():
    """UID filtering is not implemented, so both UID ranges alert."""

    events = [
        make_event("1", "system_user", 500),
        make_event("2", "human_user", 1001),
    ]

    alerts = NewUserCreationRule().evaluate(events)

    assert len(alerts) == 2
    assert alerts[0].event.raw_data["uid"] == 500
    assert alerts[1].event.raw_data["uid"] == 1001

def test_non_user_added_events_are_ignored():
    """Events other than USER_ADDED should not create alerts."""

    events = [
        make_event(
            "1",
            "alice",
            1001,
            "ssh_accepted_password",
        ),
        make_event(
            "2",
            "bob",
            1002,
            "sudo_command",
        ),
    ]

    alerts = NewUserCreationRule().evaluate(events)

    assert alerts == []