"""dedicated tests for Rule 8: suspicious User-Agent detection."""

from datetime import datetime, timezone

from app.detection.engine import DetectionEngine
from app.detection.rules.suspicious_user_agent import SuspiciousUserAgentRule
from app.models.normalized_event import NormalizedEvent

BASE_TIME = datetime(2026, 8, 26, 20, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    user_agent: str,
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
            "path": "/",
            "query_string": "",
            "user_agent": user_agent,
            "status_code": 200,
        },
    )

def test_sqlmap_user_agent_triggers():
    """sqlmap User-Agent should trigger a low-severity alert."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("sqlmap", "sqlmap/1.8")]
    )

    assert len(alerts) == 1
    assert alerts[0].rule_name == "suspicious_user_agent"
    assert alerts[0].severity == "low"

def test_nikto_user_agent_triggers():
    """Nikto User-Agent should trigger."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("nikto", "Nikto/2.5.0")]
    )

    assert len(alerts) == 1

def test_curl_user_agent_triggers():
    """curl User-Agent should trigger."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("curl", "curl/8.5.0")]
    )

    assert len(alerts) == 1

def test_python_requests_user_agent_triggers():
    """python-requests User-Agent should trigger."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("python-requests", "python-requests/2.32.0")]
    )

    assert len(alerts) == 1

def test_nmap_user_agent_triggers():
    """nmap User-Agent should trigger."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("nmap", "Nmap Scripting Engine")]
    )

    assert len(alerts) == 1

def test_masscan_user_agent_triggers():
    """masscan User-Agent should trigger."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("masscan", "masscan/1.3")]
    )

    assert len(alerts) == 1

def test_empty_user_agent_triggers():
    """An empty User-Agent should trigger a low-severity alert."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("empty", "")]
    )

    assert len(alerts) == 1
    assert alerts[0].severity == "low"
    assert "missing User-Agent" in alerts[0].message

def test_normal_browser_does_not_trigger():
    """A normal browser User-Agent should not trigger."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("browser", "Mozilla/5.0")]
    )

    assert alerts == []

def test_non_access_event_is_ignored():
    """Non-access events should be ignored."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [
            make_event(
                "ssh",
                "sqlmap/1.8",
                source_type="auth",
                event_type="ssh_failed_password",
            )
        ]
    )

    assert alerts == []

def test_case_insensitive_matching():
    """Tool matching should be case-insensitive."""

    alerts = SuspiciousUserAgentRule().evaluate(
        [make_event("case", "SQLMAP/1.8")]
    )

    assert len(alerts) == 1

def test_only_suspicious_events_generate_alerts():
    """Only suspicious or missing User-Agent should generate alerts."""

    events = [
        make_event("sqlmap", "sqlmap/1.8"),
        make_event("browser", "Mozilla/5.0"),
        make_event("curl", "curl/8.5.0"),
    ]

    alerts = SuspiciousUserAgentRule().evaluate(events)

    assert len(alerts) == 2
    assert {alert.event.event_id for alert in alerts} == {
        "sqlmap",
        "curl",
    }

def test_engine_runs_suspicious_user_agent_rule():
    """DetectionEngine should execute Rule 8."""

    events = [
        make_event("engine", "sqlmap/1.8")
    ]

    engine = DetectionEngine()
    engine.register_rule(SuspiciousUserAgentRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "suspicious_user_agent"
    assert alerts[0].event.event_id == "engine"