"""Detection rule for suspicious User-Agent strings."""

from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

SUSPICIOUS_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "curl",
    "python-requests",
    "nmap",
    "masscan",
]

class SuspiciousUserAgentRule(DetectionRule):
    """Detect known scanning tools and missing User-Agent strings."""

    def evaluate(
        self,
        events: List[NormalizedEvent],
    ) -> List[Alert]:
        """Return low-severity alerts for suspicious User-Agent values."""
        alerts: List[Alert] = []

        for event in events:
            if event.source_type != "access":
                continue

            user_agent = str(event.raw_data.get("user_agent") or "").strip()

            suspicious_tool = any(
                tool in user_agent.lower()
                for tool in SUSPICIOUS_USER_AGENTS
            )

            if not user_agent or suspicious_tool:
                reason = (
                    "missing User-Agent"
                    if not user_agent
                    else f"suspicious User-Agent: {user_agent}"
                )

                alerts.append(
                    Alert(
                        rule_name="suspicious_user_agent",
                        severity="low",
                        message=(
                            f"Suspicious web client from "
                            f"{event.source_ip}: {reason}"
                        ),
                        event=event,
                    )
                )
        return alerts
