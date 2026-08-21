"""Core detection engine for running registered detection rules."""

from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

class DetectionEngine:
    """Run registered detection rules against normalized events."""

    def __init__(self) -> None:
        """Initialize an empty detection engine."""
        self.rules: List[DetectionRule] = []

    def register_rule(self, rule: DetectionRule) -> None:
        """Register a detection rule with the engine."""
        self.rules.append(rule)

    def run(self, events: List[NormalizedEvent]) -> List[Alert]:
        """Run all registered rules and collect their alerts."""
        alerts: List[Alert] = []

        for rule in self.rules:
            alerts.extend(rule.evaluate(events))

        return alerts