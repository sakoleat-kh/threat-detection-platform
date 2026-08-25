"""Detection rule for suspicious directory scanning."""

from collections import defaultdict, deque
from datetime import timedelta
from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

class DirectoryScanningRule(DetectionRule):
    """Detect many distinct paths with a high 404 ratio from one IP."""

    def __init__(
        self,
        path_threshold: int = 15,
        not_found_ratio: float = 0.80,
        window_minutes: int = 5,
    ) -> None:
        """Initialize directory scanning threshoulds."""
        self.path_threshold = path_threshold
        self.not_found_ratio = not_found_ratio
        self.window = timedelta(minutes=window_minutes)

    def evaluate(
        self,
        events: List[NormalizedEvent],
    ) -> List[Alert]:
        """Return alerts for suspicious directory scanning."""
        events_by_ip = defaultdict(list)

        for event in events:
            if event.source_type != "access":
                continue

            if event.source_ip is None:
                continue

            if "path" not in event.raw_data:
                continue

            events_by_ip[event.source_ip].append(event)

        alerts: List[Alert] = []

        for source_ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda event: event.timestamp)

            window = deque()

            for event in ip_events:
                window.append(event)

                while (
                    window
                    and event.timestamp - window[0].timestamp
                    > self.window
                ):
                    window.popleft()

                paths = {
                    item.raw_data["path"]
                    for item in window
                    if "path" in item.raw_data
                }

                if len(paths) < self.path_threshold:
                    continue

                not_found_count = sum(
                    item.raw_data.get("status_code") == 404
                    for item in window
                )

                not_found_ratio = not_found_count / len(window)

                if not_found_ratio >= self.not_found_ratio:
                    alerts.append(
                        Alert(
                            rule_name="directory_scanning",
                            severity="high",
                            message=(
                                f"Directory scanning detected from "
                                f"{source_ip}: {len(paths)} distinct paths, "
                                f"{not_found_ratio:.0%} 404 responses"                            ),
                            event=event,
                        )
                    )
                    break

        return alerts
