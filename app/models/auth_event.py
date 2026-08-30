"""Data model for Linux authentication log events."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

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
    pid: Optional[int]
    event_type: EventType
    username: Optional[str]
    source_ip: Optional[str]
    port: Optional[int]
    command: Optional[str]
    target_user: Optional[str]
    uid: Optional[int]
    gid: Optional[int]
    home_dir: Optional[str]
