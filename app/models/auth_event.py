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

if __name__ == "__main__":
    event = AuthLogEvent(
        raw_line=(

            "Aug 6 09:15:22 ubuntu sshd[2543]:"
            "Failed password for invalid user admin "
            "from 192.168.1.15 port 51234 ssh2"
        ),
        timestamp=datetime("2026,8, 6, ,9, 15, 22"),
        host="ubuntu",
        process="sshd",
        pid=2543,
        event_type=EventType.SSH_FAILED_PASSWORD,
        username="admin",
        source_ip="192.168.1.15",
        port=51234,
        command=None,
        target_user=None,
    )
    print(event)