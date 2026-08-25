"""Dedicated tests for Rule 5: directory scanning."""

from datetime import datetime, timedelta, timezone

from app.detection.rules.directory_scanning import DirectoryScanningRule
from app.models.normalized_event import NormalizedEvent
from app.detection.engine import DetectionEngine


BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    source_ip: str,
    timestamp: datetime,
    path: str,
    status_code: int,
) -> NormalizedEvent:
    """Create a normalized access event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="access",
        source_ip=source_ip,
        username=None,
        raw_event_type="access",
        raw_data={
            "path": path,
            "status_code": status_code,
        },
    )

def make_events(
    source_ip: str,
    count: int,
    status_code: int = 404,
    start_time: datetime = BASE_TIME,
) -> list[NormalizedEvent]:
    """create access events with distinct paths."""
    return [
        make_event(
            str(i),
            source_ip,
            start_time + timedelta(seconds=i * 10),
            f"/scan-{i}",
            status_code,
        )
        for i in range(count)
    ]

def test_below_path_threshold_does_not_trigger():
    """Fewer than 15 distinct paths should not trigger."""

    events = make_events("10.0.0.1", 14)

    alerts = DirectoryScanningRule().evaluate(events)

    assert alerts == []

def test_fifteen_distinct_paths_with_high_404_ratio_trigger():
    """15 distinct paths with a high 404 ratio should trigger."""

    events = make_events("10.0.0.1", 15)

    alerts = DirectoryScanningRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "directory_scanning"
    assert alerts[0].event.source_ip == "10.0.0.1"

def test_low_404_ratio_does_not_trigger():
    """15 distinct paths with a low 404 ratio should not trigger."""

    events = [
        *make_events("10.0.0.1", 5, 404),
        *make_events(
            "10.0.0.1",
            10,
            200,
            BASE_TIME + timedelta(minutes=1),
        ),
    ]

    alerts = DirectoryScanningRule().evaluate(events)

    assert alerts == []

def test_repeated_same_path_does_not_trigger():
    """repeated requests to one path are not directory scanning."""

    events = [
        make_event(
            str(i),
            "10.0.0.1",
            BASE_TIME + timedelta(seconds=i * 10),
            "/admin",
            404,
        )
        for i in range(20)
    ]

    alerts = DirectoryScanningRule().evaluate(events)

    assert alerts == []

def test_different_ips_are_isolated():
    """Paths from different IPs must not be combined."""

    events = [
        *make_events("10.0.0.1", 8),
        *make_events("10.0.0.2", 8),
    ]

    alerts = DirectoryScanningRule().evaluate(events)

    assert alerts == []

def test_events_spread_outside_window_do_not_trigger():
    """Distinct paths outside the five-minute window should not combine."""

    events = make_events(
        "10.0.0.1",
        15,
        404,
        BASE_TIME,
    )

    events = [
        make_event(
            event.event_id,
            event.source_ip,
            BASE_TIME + timedelta(minutes=i),
            event.raw_data["path"],
            event.raw_data["status_code"],
        )
        for i, event in enumerate(events)
    ]

    alerts = DirectoryScanningRule().evaluate(events)

    assert alerts == []

def test_exactly_eighty_precent_404_triggers():
    """Exactly 80% 404 responses should satisfy the threshold."""

    events = [
        *make_events("10.0.0.1", 16, 404),
        *make_events(
            "10.0.0.1",
            4,
            200,
            BASE_TIME + timedelta(minutes=1),
        ),
    ]

    alerts = DirectoryScanningRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "directory_scanning"

def test_engine_runs_directory_scanning_rule():
    """DetectionEngine should execute Rule 5."""

    events = make_events("10.0.0.5", 15)

    engine = DetectionEngine()
    engine.register_rule(DirectoryScanningRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "directory_scanning"
    assert alerts[0].event.source_ip == "10.0.0.5"