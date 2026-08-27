"""Data model for detection alerts."""

from dataclasses import dataclass
from app.models.normalized_event import NormalizedEvent

@dataclass
class Alert:
    """Represents a detection generated from a normalized event."""

    rule_name: str
    severity: str
    message: str
    event: NormalizedEvent
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    mitre_tactic: str | None = None
