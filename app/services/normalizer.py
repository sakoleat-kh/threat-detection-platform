"""Normalize source-specific security events into a common schema."""

from dataclasses import asdict

from app.models.auth_event import AuthLogEvent
from app.models.normalized_event import NormalizedEvent

def normalize_auth_event(event: AuthLogEvent) -> NormalizedEvent:
    """Convert an AuthLogEvent into a NormalizedEvent."""

    raw_data = asdict(event)

    raw_data.pop("raw_line", None)
    raw_data.pop("timestamp", None)
    raw_data.pop("host", None)
    raw_data.pop("event_type", None)
    raw_data.pop("source_ip", None)
    raw_data.pop("username", None)

    event_type = event.event_type.value

    return NormalizedEvent(
        event_id=f"auth-{id(event)}",
        timestamp=event.timestamp,
        source_type="auth",
        source_ip=event.source_ip,
        username=event.username,
        raw_event_type=event_type,
        raw_data=raw_data,
    )
