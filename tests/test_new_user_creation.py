"""Tests for new user creation detection."""

from datetime import datetime, timezone

from app.detection.engine import DetectionEngine
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

def test_user_added_creates_alert():
    """Every user_added event should create an alert."""

    events = [
        make_event("1", "alice", 1001),
        make_event("2", "bob", 1002),
    ]

    alerts = NewUserCreationRule().evaluate(events)

    assert len(alerts) == 2
    assert alerts[0].event.username == "alice"
    assert alerts[1].event.username == "bob"

def test_system_uid_still_creates_alert():
    """UID below 1000 should still create an alert."""

    events = [
        make_event("1", "system_user", 500),
    ]

    alerts = NewUserCreationRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.raw_data["uid"] == 500

def test_non_user_added_event_is_ignored():
    """Other event types should not create alerts."""

    events = [
        make_event(
            "1",
            "alice",
            1001,
            "ssh_accepted_password",
        )
    ]

    alerts = NewUserCreationRule().evaluate(events)

    assert alerts == []

def test_engine_runs_new_user_creation_rule():
    """detectionengine should execute Rule 4."""

    events = [
        make_event("1", "alice", 1001),
    ]
    engine = DetectionEngine()
    engine.register_rule(NewUserCreationRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "new_user_creation"
    assert alerts[0].event.username == "alice"