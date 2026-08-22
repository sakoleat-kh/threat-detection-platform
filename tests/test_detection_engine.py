"""Tests for the detection engine."""

import logging

from datetime import datetime, timezone

from app.detection.engine import DetectionEngine
from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent


class TestRule(DetectionRule):
    """Test rule used to verity DetectionEngine behavior."""

    def evaluate(self, events):
        """Generate alerts for auth events."""        
        return [
            Alert(
                rule_name="test_auth_rule",
                severity="low",
                message="Test auth event",
                event=event,
            )
            for event in events
            if event.source_type == "auth"
        ]
def test_engine_runs_registered_rule_and_collects_alerts():
    """The engine should run registered rules and collect thire alerts."""

    events = [
        NormalizedEvent(
            event_id="auth-1",
            timestamp=datetime.now(timezone.utc),
            source_type="auth",
            source_ip=None,
            username="ubuntu",
            raw_event_type="sudo_command",
            raw_data={},
        ),
        NormalizedEvent(
            event_id="auth-2",
            timestamp=datetime.now(timezone.utc),
            source_type="auth",
            source_ip=None,
            username="root",
            raw_event_type="login",
            raw_data={},
        ),
        NormalizedEvent(
            event_id="access-1",
            timestamp=datetime.now(timezone.utc),
            source_type="access",
            source_ip="192.168.1.10",
            username=None,
            raw_event_type="access",
            raw_data={},
        ),
    ]

    engine = DetectionEngine()
    engine.register_rule(TestRule())

    alerts = engine.run(events)

    assert len(alerts) == 2
    assert all(alert.rule_name == "test_auth_rule" for alert in alerts)
    assert alerts[0].event.event_id == "auth-1"
    assert alerts[1].event.event_id == "auth-2"


class FailingRule(DetectionRule):
    """Test rule that deliberately raises an exceptions."""

    def evaluate(self, events):
        """Raise an exception to test engine resilience."""
        raise ValueError("intentional test failure")

    def test_engine_continues_when_rule_raises_exception(caplog):
        """A failing rule should not prevent later rules from running."""

        events = [
            NormalizedEvent(
                event_id="auth-1",
                timestamp=datetime.now(timezone.utc),
                source_type="auth",
                source_ip=None,
                username="ubuntu",
                raw_event_type="unknown",
                raw_data={},
            ),
        ]
        engine = DetectionEngine()

        engine.register_rule(FailingRule())
        engine.register_rule(TestRule())

        with caplog.at_level(logging.ERROR):
            alerts = engine.run(events)

        assert len(alerts) == 1
        assert alerts[0].rule_name == "test_auth_rule"
        assert "FailingRule" in caplog.text
        assert "intentional test failure" in caplog.text

    def test_engine_with_empty_events_returns_no_alerts():
        """an empty event list should produce zero alers."""

        engine = DetectionEngine()
        engine.register_rule(TestRule())

        alerts = engine.run([])

        assert alerts == []