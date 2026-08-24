"""Detection rule for successful SSH login after repeated failures."""

from collections import defaultdict, deque
from datetime import timedelta
from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

class SuccessfulAfterFailuresRule(DetectionRule):
    """Detect successful SSH login following repeated failures."""

    def __init__(
        self,
        threshold: int = 3,
        window_minutes: int = 5,
    ) -> None:
        """Initialize the rule with threshold and time-window settings."""
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def evaluate(
        self,
        events: List[NormalizedEvent],
    ) -> List[Alert]:
        """Return alerts for successful logins preceded by failures."""
        events_by_ip = defaultdict(list)

        for event in events:
            if event.source_ip is None:
                continue

            if event.raw_event_type not in {
                "ssh_failed_password",
                "ssh_accepted_password",
            }:
                continue
            events_by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []

        for source_ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda event: event.timestamp)

            failed_window  = deque()

            for event in ip_events:
                if event.raw_event_type == "ssh_failed_password":
                    failed_window.append(event)

                    while (
                        event.timestamp - failed_window[0].timestamp
                        > self.window
                    ):
                        failed_window.popleft()

                elif event.raw_event_type == "ssh_accepted_password":
                    while (
                        failed_window
                        and event.timestamp - failed_window[0].timestamp
                        > self.window
                    ):
                        failed_window.popleft()

                    if len(failed_window) >= self.threshold:
                        alerts.append(
                            Alert(
                                rule_name="successful_after_failures",
                                severity="high",
                                message=(
                                    f"Successful SSH login from {source_ip} "
                                    f"after {len(failed_window)} failed attempts"
                                ),
                                event=event,
                            )
                        )
                        break

        return alerts
