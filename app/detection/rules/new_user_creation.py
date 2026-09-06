"""Detect every newly created user account."""

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent


class NewUserCreationRule(DetectionRule):
    """detect every newly created user account."""

    def evaluate(
        self,
        events: list[NormalizedEvent],
    ) -> list[Alert]:
        """Return an alert for every user-added event."""
        alerts: list[Alert] = []

        for event in events:
            if event.raw_event_type != "user_added":
                continue

            username = event.username or "unknown"
            uid = event.raw_data.get("uid")

            alerts.append(
                Alert(
                    rule_name="new_user_creation",
                    severity="high",
                    message=(
                        f"New user created: {username}"
                        f" (UID: {uid})"
                    ),
                    event=event,
                )
            )
        return alerts