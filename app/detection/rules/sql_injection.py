"""Detection rule for SQL injection attempts."""

import re
from typing import List

from app.detection.rule_base import DetectionRule
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent

SQLI_PATTERNS = [
    # Boolean=based
    re.compile(r"""(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+""", re.IGNORECASE),

    # UNION-based
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),

    # SELECT
    re.compile(r"\bselect\s+.+\s+\bfrom\b", re.IGNORECASE),

    # INSERT
    re.compile(r"\binsert\s+into\b", re.IGNORECASE),

    # UPDATE
    re.compile(r"\bupdate\s+\w+\s+set\b", re.IGNORECASE),

    # DELETE
    re.compile(r"\bdelete\s+from\b", re.IGNORECASE),

    # DROP
    re.compile(r"\bdrop\s+(?:table|database)\b", re.IGNORECASE),

    # SQL comments
    re.compile(r"--\s*(?:$|[^\r\n])", re.IGNORECASE),
    re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),

    # OWASP-inspired additions
    re.compile(r"\bhaving\s+\d+\s*=\s*\d+", re.IGNORECASE),
    re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
    re.compile(r";\s*(?:select|insert|update|delete|drop)\b", re.IGNORECASE),
    re.compile(r"""(?:'|\")\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?""", re.IGNORECASE),
    re.compile(r"(?:^|[\s'\";])#(?:\s|$)", re.IGNORECASE),

]

class SQLInjectionRule(DetectionRule):
    """Detect recognizable SQL injection payloads."""

    def evaluate(
        self,
        events: List[NormalizedEvent],
    ) -> List[Alert]:
        """Return alerts for access events matching SQLI signatures."""
        alerts: List[Alert] = []

        for event in events:
            if event.source_type != "access":
                continue

            path = str(event.raw_data.get("path") or "")
            query_string = str(event.raw_data.get("query_string") or "")

            target = f"{path}?{query_string}"

            for pattern in SQLI_PATTERNS:
                if pattern.search(target):
                    alerts.append(
                        Alert(
                            rule_name="sql_injection",
                            severity="high",
                            message=(
                                f"Possible SQL injection attempt from "
                                f"{event.source_ip}"
                            ),
                            event=event,
                        )
                    )
                    break

        return alerts