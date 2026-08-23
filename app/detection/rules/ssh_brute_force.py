"""SSH brute-force detection rule."""

from collections import defaultdict, deque
from datetime import timedelta
from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent


class SSHBruteForceRule(DetectionRule):
    """Detect repeated failed SSH authentication attempts from one IP."""

    def __init__(
        self,
        threshold: int = 5,
        window_minutes: int = 5,
    ) -> None:
        """Initialize the rule with threshold and time-window settings."""
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def evaluate(self, events: List[NormalizedEvent]) -> List[Alert]:
        """Return alerts for source IPs reaching the threshold within the window."""
        events_by_ip = defaultdict(list)

        for event in events:
            if event.raw_event_type != "ssh_failed_password":
                continue

            if event.source_ip is None:
                continue

            events_by_ip[event.source_ip].append(event)

        alerts: list[Alert] = []

        for source_ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda event: event.timestamp)

            window = deque()

            for event in ip_events:
                window.append(event)

                while(
                    event.timestamp - window[0].timestamp
                    > self.window
                ):
                    window.popleft()

                if len(window) >= self.threshold:
                    alerts.append(
                        Alert(
                            rule_name="ssh_brute_force",
                            severity="high",
                            message=(
                                f"{len(window)} failed SSH logins "
                                f"from {source_ip} within "
                                f"{self.window.total_seconds() / 60:g} minutes"
                            ),
                            event=event,
                        )
                    )

                    break

        return alerts
