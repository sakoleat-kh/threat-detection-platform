"""SSH brute-force detection rule."""

from collections import defaultdict
from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent


class SSHBruteForceRule(DetectionRule):
    """Detect repeated failed SSH authentication attempts from one IP."""

    def __init__(self, threshold: int = 5) -> None:
        """Initialize the rule with a failure threshold."""
        self.threshold = threshold

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        """Return alerts for source IPs reaching the failure threshold."""
        failed_counts = defaultdict(int)
        alerts: list[Alert] = []

        for event in events:
            if event.raw_event_type != "ssh_failed_password":
                continue

            if event.source_ip is None:
                continue

            failed_counts[event.source_ip] += 1

        for source_ip, count in failed_counts.items():
            if count >= self.threshold:
                matching_event = next(
                    event
                    for event in events
                    if (
                        event.source_ip == source_ip
                        and event.raw_event_type == "ssh_failed_password"
                    )
                )

                alerts.append(
                    Alert(
                        rule_name="ssh_brute_force",
                        severity="high",
                        message=f"{count} failed SSH logins from {source_ip}",
                        event=matching_event,
                    )
                )


        return alerts
