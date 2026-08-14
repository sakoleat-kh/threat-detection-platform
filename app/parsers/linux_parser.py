import re
from typing import Optional

from app.models.auth_event import AuthLogEvent, EventType

BASE_SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_.-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

FAILED_PASSWORD_PATTERN = re.compile(
    r"^Failed password for "
    r"(?:(?:invalid user)\s+)?"
    r"(?P<username>\S+)\s+"
    r"from\s+"
    r"(?P<source_ip>\S+)\s+"
    r"port\s+"
    r"(?P<port>\d+)"
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"^Accepted password for "
    r"(?P<username>\S+)\s"
    r"from\s+"
    r"(?P<source_ip>\S+)\s+"
    r"port\s+"
    r"(?P<port>\d+)"
)

INVALID_USER_PATTERN = re.compile(
    r"^Invalid user "
    r"(?P<username>\S+)\s+"
    r"from\s+"
    r"(?P<source_ip>\S+)\s+"
    r"port\s+"
    r"(?P<port>\d+)"
)

def parse_line(raw_line: str) -> Optional[AuthLogEvent]:
    """
    Parse one Linux auth.log line.
    Returns:
        AuthLogEvent: when the line is a valid syslog entry.
        None: when the line dose not match the base syslog format.
    
    """

    raw_line = raw_line.rstrip("\n")

    base_match = BASE_SYSLOG_PATTERN.match(raw_line)

    if not base_match:
        return None

    base = base_match.groupdict()

    pid = int(base["pid"]) if base["pid"] is not None else None
    message = base["message"]


    match = FAILED_PASSWORD_PATTERN.match(message)

    if match:
        data = match.groupdict()

        return AuthLogEvent(
            raw_line = raw_line,
            timestamp = f"{base['month']} {base['day']} {base['time']}",
            host = base["host"],
            process = base["process"],
            pid = pid,
            event_type = EventType.SSH_FAILED_PASSWORD,
            username = data["username"],
            source_ip = data["source_ip"],
            port = int(data["port"]),
        )

    match = ACCEPTED_PASSWORD_PATTERN.match(message)
    if match:
        data = match.groupdict()

        return AuthLogEvent(
            raw_line = raw_line,
            timestamp = f"{base['month']} {base['day']} {base['time']}",
            host = base["host"],
            process = base["process"],
            pid = pid,
            event_type = EventType.SSH_ACCEPTED_PASSWORD,
            username = data["username"],
            source_ip = data["source_ip"],
            port = int(data["port"]),
        )

    match = INVALID_USER_PATTERN.match(message)

    if match:
        data = match.groupdict()

        return AuthLogEvent(
            raw_line = raw_line,
            timestamp = f"{base['month']} {base['day']} {base['time']}",
            host = base["host"],
            process = base["process"],
            pid = pid,
            event_type = EventType.SSH_INVALID_USER,
            username = data["username"],
            source_ip = data["source_ip"],
            port = int(data["port"]),
        )

    return AuthLogEvent(
        raw_line = raw_line,
        timestamp = f"{base['month']} {base['day']} {base['time']}",
        host = base["host"],
        process = base["process"],
        pid = pid,
        event_type = EventType.UNKNOWN,
        username = None,
        source_ip = None,
        port = None,
    )

if __name__ == "__main__":

    sample_lines = [
        "Aug  6 09:15:22 ubuntu sshd[2543]: Failed password for invalid user admin from 192.168.1.15 port 51234 ssh2",
        "Aug  6 09:16:22 ubuntu sshd[2544]: Accepted password for sakol from 192.168.1.20 port 41234 ssh2",
        "Aug  6 09:17:22 ubuntu sshd[2545]: Invalid user test from 10.0.0.5 port 33333",
        "Aug  6 09:18:22 ubuntu sshd[2546]: Some unknown SSH event",
    ]

    for line in sample_lines:
        event = parse_line(line)
        print(event)