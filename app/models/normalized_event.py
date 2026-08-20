"""Data model for normalized security events."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

@dataclass
class NormalizedEvent:
    """Common event representation consumed by the detection engine."""

    event_id: str
    timestamp: datetime
    source_type: str
    source_ip: str | None
    username: str | None
    raw_event_type: str
    raw_data: dict[str, Any]