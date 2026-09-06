"""Data model for Linux authentication log events."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class EventType(Enum):
    SSH_FAILED_PASSWORD = "ssh_failed_password"
    SSH_ACCEPTED_PASSWORD = "ssh_accepted_password"
    SSH_INVALID_USER = "ssh_invalid_user"
    SUDO_COMMAND = "sudo_command"
    SUDO_AUTH_FAILURE = "sudo_auth_failed"
    USER_LOGIN = "user_login"
    USER_ADDED = "user_added"
    UNKNOWN = "unknown"


@dataclass
class AuthLogEvent:
    raw_line: str
    timestamp: datetime
    host: str
    process: str
    pid: int | None
    event_type: EventType
    username: str | None
    source_ip: str | None
    port: int | None
    command: str | None
    target_user: str | None
    uid: int | None
    gid: int | None
    home_dir: str | None
