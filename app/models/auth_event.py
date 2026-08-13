from dataclasses import dataclass
from enum import Enum
from typing import Optional

class EventType(Enum):
    SSH_FAILED_PASSWORD = "ssh_failed_password"
    SSH_ACCEPTED_PASSWORD = "ssh_accepted_password"
    SSH_INVALID_KEY = "ssh_invalid_key"
    SUDO_COMMAND = "sudo_command"
    SUDO_AUTH_FAILED = "sudo_auth_failed"
    USER_LOGIN = "user_login"
    UNKNOWN = "unknown"

@dataclass
class AuthLogEvent:
    raw_line: str
    timestamp: str
    host: str
    process: str
    pid: Optional[int]
    event_type: EventType
    username: Optional[str]
    source_ip: Optional[str]
    port: Optional[int]

if __name__ == "__main__":
    event = AuthLogEvent(
        raw_line=(

            "Aug 6 09:15:22 ubuntu sshd[2543]:"
            "Failed password for invalid user admin "
            "from 192.168.1.15 port 51234 ssh2"
        ),
        timestamp="Aug 6 09:15:22",
        host="ubuntu",
        process="sshd",
        pid=2543,
        event_type=EventType.SSH_FAILED_PASSWORD,
        username="admin",
        source_ip="192.168.1.15",
        port=51234,
    )
    print(event)