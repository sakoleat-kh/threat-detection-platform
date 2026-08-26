"""Dedicated tests for Rule 6: SQL injection detection."""

from datetime import datetime, timezone

from app.detection.rules.sql_injection import SQLInjectionRule
from app.models.normalized_event import NormalizedEvent
from app.detection.engine import DetectionEngine


BASE_TIME = datetime(2026, 8, 26, 15, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    path: str,
    query_string: str,
    source_type: str = "access",
    event_type: str = "access",
) -> NormalizedEvent:
    """Create a normalized access event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=BASE_TIME,
        source_type=source_type,
        source_ip="10.0.0.5",
        username=None,
        raw_event_type=event_type,
        raw_data={
            "path": path,
            "query_string": query_string,
            "status_code": 200,
        },
    )

def test_boolean_based_sqli_in_query_triggers():
    """A recognizable boolean SQLI payload should trigger."""

    events = [
        make_event(
            "1",
            "/search",
            "q=' OR 1=1 --",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "sql_injection"
    assert alerts[0].event.event_id == "1"

def test_union_select_sqli_triggers():
    """A UNION SELECT payload should trigger."""

    events = [
        make_event(
            "1",
            "/product",
            "id=1 UNION SELECT username,password FROM users"
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_sqli_in_path_triggers():
    """A SQLI signature in the path should trigger."""

    events = [
        make_event(
            "1",
            "/products/1 UNION SELECT password FROM users",
            "",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "sql_injection"

def test_normal_request_does_not_trigger():
    """A normal web request should not trigger."""

    events = [
        make_event(
            "1",
            "/products",
            "id=123&category=books",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert alerts == []

def test_non_access_event_is_ignored():
    """Non-access events should be ignored."""

    events = [
        make_event(
            "1",
            "/search",
            "q=' OR 1=1 --",
            source_type="auth",
            event_type="ssh_failed_password",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert alerts == []

def test_url_encoded_boolean_sqli_is_not_currently_detected():
    """URL-encoded SQLi is a documented current limitation."""

    events = [
        make_event(
            "1",
            "/search",
            "q=%27%20OR%201%3D1",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert alerts == []

def test_only_matching_events_generate_alerts():
    """Only events containing SQLi signatures should generate alerts."""

    events = [
        make_event(
            "malicious",
            "/search",
            "q=' OR 1=1 --",
        ),
        make_event(
            "normal",
            "/products",
            "id=123",
        ),
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.event_id == "malicious"

def test_engine_runs_sql_injection_rule():
    """DetectionEngine should execute Rule 6."""

    events = [
        make_event(
            "malicious",
            "/search",
            "q=' OR 1=1 --",
        )
    ]

    engine = DetectionEngine()
    engine.register_rule(SQLInjectionRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "sql_injection"
    assert alerts[0].event.event_id == "malicious"