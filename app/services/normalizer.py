"""Normalize source-specific security events into a common schema."""

from dataclasses import asdict

from app.models.auth_event import AuthLogEvent
from app.models.normalized_event import NormalizedEvent
from app.models.access_event import AccessLogEvent

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

def normalize_access_event(event: AccessLogEvent) -> NormalizedEvent:
    """Convert an AccessLogEvent into a NormalizedEvent."""

    raw_data = asdict(event)

    raw_data.pop("client_ip", None)
    raw_data.pop("timestamp", None)
    raw_data.pop("remote_logname", None)
    raw_data.pop("authenticated_user", None)
    raw_data.pop("request", None)

    return NormalizedEvent(
        event_id=f"access-{id(event)}",
        timestamp=event.timestamp,
        source_type="access",
        source_ip=event.client_ip,
        username=(
            event.authenticated_user
            if event.authenticated_user != "-"
            else None
        ),
        raw_event_type="access",
        raw_data=raw_data,
    )