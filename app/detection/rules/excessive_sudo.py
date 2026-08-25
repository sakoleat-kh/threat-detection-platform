"""Detection rule for excessive sudo usage."""

from collections import defaultdict, deque
from datetime import timedelta
from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

class ExcessiveSudoRule(DetectionRule):
    """Detect excessive sudo commands and repeated sudo failures."""

    def __init__(
        self,
        command_threshold: int = 10,
        failure_threshold: int = 3,
        window_minutes: int = 5,
    ) -> None:
        """Initialize sudo thresholds and time window."""
        self.command_threshold = command_threshold
        self.failure_threshold = failure_threshold
        self.window = timedelta(minutes=window_minutes)

    def evaluate(
        self,
        events: List[NormalizedEvent],
    ) -> List[Alert]:
        """Return alerts for excessive sudo activity."""
        events_by_source = defaultdict(list)

        for event in events:
            if event.source_type != "auth":
                continue

            if event.raw_event_type not in {
                "sudo_command",
                "sudo_auth_failed",
            }:
                continue

            source = event.username or event.source_ip

            if source is None:
                continue

            events_by_source[source].append(event)

        alerts: List[Alert] = []

        for source, source_events in events_by_source.items():
            source_events.sort(key=lambda event: event.timestamp)

            command_window = deque()
            failure_window = deque()

            for event in source_events:
                if event.raw_event_type == "sudo_command":
                    command_window.append(event)

                    while (
                        event.timestamp - command_window[0].timestamp
                        >self.window
                    ):
                        command_window.popleft()

                    if len(command_window) >= self.command_threshold:
                        alerts.append(
                            Alert(
                                rule_name="excessive_sudo",
                                severity="high",
                                message=(
                                    f"{len(command_window)} sudo commands "
                                    f"from {source} within "
                                    f"{self.window.total_seconds() / 60:g} minutes"
                                ),
                                event=event,
                            )
                        )
                        break
                elif event.raw_event_type == "sudo_auth_failed":
                    failure_window.append(event)

                    while (
                        event.timestamp - failure_window[0].timestamp
                        > self.window
                    ):
                        failure_window.popleft()
                    if len(failure_window) >= self.failure_threshold:
                        alerts.append(
                            Alert(
                                rule_name="excessive_sudo",
                                severity="high",
                                message=(
                                    f"{len(failure_window)} sudo "
                                    f"authentication failures from {source} "
                                    f"within "
                                    f"{self.window.total_seconds() / 60:g} minutes"
                                ),
                                event=event,
                            )
                        )
                        break

        return alerts
