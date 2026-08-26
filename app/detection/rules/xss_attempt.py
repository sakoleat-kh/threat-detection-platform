"""Detection rule for cross-site scripting attempts."""

import re
from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

XSS_PATTERNS = [
    # Script tag injection
    re.compile(
        r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*",
        re.IGNORECASE | re.DOTALL,
    ),

    # JavaScript URL
    re.compile(
        r"\bjavascript\s*:",
        re.IGNORECASE,
    ),

    # Common inline event handlers
    re.compile(
        r"\bon(?:error|load|click|mouseover|focus)\s*=",
        re.IGNORECASE,
    ),

    # Common executable HTML element
    re.compile(
        r"<\s*(?:img|svg|iframe|object|embed)\b[^>]*>",
        re.IGNORECASE,
    ),

    # HTML/script breaking with an injected tag
    re.compile(
        r"""(?:["']\s*>\s*|<\s*/?\s*(?:script|style)\b)""",
        re.IGNORECASE,
    ),
]

class XSSAttemptRule(DetectionRule):
    """detect recognizable XSS payloads in access events."""

    def evaluate(
        self,
        events: List[NormalizedEvent],
    ) -> List[Alert]:
        """Return alerts for access events matching XSS signatures."""
        alerts: List[Alert] = []

        for event in events:
            if event.source_type != "access":
                continue

            path = str(event.raw_data.get("path") or "")
            query_string = str(event.raw_data.get("query_string") or "")

            target = f"{path}?{query_string}"

            for pattern in XSS_PATTERNS:
                if pattern.search(target):
                    alerts.append(
                        Alert(
                            rule_name="xss_attempt",
                            severity="high",
                            message=(
                                f"Possible XSS attempt from "
                                f"{event.source_ip}"
                            ),
                            event=event,
                        )
                    )
                    break
        return alerts