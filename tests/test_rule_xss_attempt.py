"""Dedicated tests for Rule 7: XSS attempt detection."""

from datetime import datetime, timezone

from app.detection.engine import DetectionEngine
from app.detection.rules.xss_attempt import XSSAttemptRule
from app.models.normalized_event import NormalizedEvent

BASE_TIME = datetime(2026, 8, 26, 15, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    path: str,
    query_string: str,
    source_type: str = "access",
    event_type: str = "access",
) -> NormalizedEvent:
    """Create a normalized event for testing."""
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

def test_script_tag_xss_triggers():
    """A script tag paylaod should trigger."""

    events = [
        make_event(
            "script",
            "/search",
            "q=<script<alert(1)</script>",
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "xss_attempt"
    assert alerts[0].event.event_id == "script"

def test_javascript_uri_triggers():
    """A javascript URI should trigger."""

    events = [
        make_event(
            "javascript-uri",
            "/redirect",
            "url=javascript:alert(1)",
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert len(alerts) == 1

def test_onerror_handler_triggers():
    """An onerror event handler should trigger."""

    events = [
        make_event(
            "onerror",
            "/search",
            "q=<img src=x onerror=alert(1)>",
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert len(alerts) == 1

def test_onclick_handler_triggers():
    """An onclick event handler should trigger."""

    events = [
        make_event(
            "onclick",
            "/search",
            'q=<a onclick="alert(1)">click</a>',
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert len(alerts) == 1

def test_xss_in_path_triggers():
    """an XSS payload in the path should trigger."""

    events = [
        make_event(
            "path-xss",
            "/search/<script>alert(1)</script>",
            "",
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.event_id == "path-xss"

def test_clean_request_does_not_trigger():
    """A normal request should not trigger."""

    events = [
        make_event(
            "clean",
            "/search",
            "q=python+security+tutorial",
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert alerts == []

def test_sql_looking_but_benign_request_does_not_trigger():
    """Normal JavaScript-related text should not trigger."""

    events = [
        make_event(
            "benign",
            "/search",
            "q=javascript+tutorial",
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert alerts == []

def test_non_access_event_is_ignored():
    """Non-access events should be ignored."""

    events = [
        make_event(
            "ssh",
            "/search",
            "q=<script>alert(1)</script>",
            source_type="auth",
            event_type="ssh_failed_password",
        )
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert alerts == []

def test_only_matching_events_generate_alerts():
    """Only matching events should generate alerts."""

    events = [
        make_event(
            "malicious",
            "/search",
            "q=<script>alert(1)</scritp>",
        ),
        make_event(
            "normal",
            "/products",
            "id=123",
        ),
    ]

    alerts = XSSAttemptRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.event_id == "malicious"

def test_engine_runs_xss_rule():
    """DetectionEngine should execute Rule 7."""

    events = [
        make_event(
            "engine-xss",
            "/search",
            "q=<script>alert(1)</script>",
        )
    ]

    engine = DetectionEngine()
    engine.register_rule(XSSAttemptRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "xss_attempt"
    assert alerts[0].event.event_id == "engine-xss"
