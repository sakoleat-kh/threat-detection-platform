"""Tests for SSH brute-force detection."""

from datetime import datetime, timezone

from app.detection.engine import DetectionEngine
from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.models.normalized_event import NormalizedEvent

def make_event(
    event_id: str,
    source_ip: str,
    event_type: str = "ssh_failed_password",
) -> NormalizedEvent:
    """Create a normalized event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source_type="auth",
        source_ip=source_ip,
        username="ubuntu",
        raw_event_type=event_type,
        raw_data={},
    )

def test_detects_five_failed_ssh_logins_from_same_ip():
    """Five failed SSH logins from one IP should trigger an alert."""

    events = [
        make_event(str(i), "10.0.0.5")
        for i in range(5)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "ssh_brute_force"
    assert alerts[0].severity == "high"
    assert alerts[0].event.source_ip == "10.0.0.5"

def test_does_not_combine_different_source_ips():
    """Failured from different IPs should have separate counters."""

    events = [
        *[make_event(str(i), "10.0.0.1") for i in range(3)],
        *[make_event(str(i + 3), "10.0.0.2") for i in range(5)],
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.source_ip == "10.0.0.2"

def test_does_not_alert_below_threshold():
    """Four failed SSH logins should not trigger the rule."""

    events = [
        make_event(str(i), "10.0.0.5")
        for i in range(4)
    ]

    alerts = SSHBruteForceRule().evaluate(events)

    assert alerts == []

def test_engine_runs_ssh_brute_force_rule():
    """DetectionEngine should execute the SSH brute-force rule."""

    events = [
        make_event(str(i), "10.0.0.5")
        for i in range(5)
    ]

    engine = DetectionEngine()
    engine.register_rule(SSHBruteForceRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "ssh_brute_force"
    assert alerts[0].event.source_ip == "10.0.0.5"