import logging
import re
from datetime import datetime
from typing import Optional

from app.models.auth_event import AuthLogEvent, EventType
from app.parsers.timestamp_utils import resolve_syslog_timestamp

logger = logging.getLogger(__name__)

BASE_SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_.-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

ISO_SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2}))\s+"
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
    r"(?P<username>\S+)\s+"
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

SUDO_COMMAND_PATTERN = re.compile(
    r"^(?P<user>\S+)\s*:\s+"
    r"TTY=(?P<tty>[^;]+)\s*;\s+"
    r"PWD=(?P<pwd>[^;]+)\s*;\s+"
    r"USER=(?P<runas_user>\S+)\s*;\s+"
    r"COMMAND=(?P<command>.*)$"
)

SUDO_AUTH_FAILURE_PATTERN = re.compile(
    r"^pam_unix\(sudo:auth\): authentication failure.*$"
)


# usermod and userdel are intentionlly out of scop for this parser task.
# Do not add parsing for those events here.
USER_ADDED_PATTERN = re.compile(
    r"^new user:\s+"
    r"name=(?P<username>[^,]+),\s+"
    r"UID=(?P<uid>\d+),\s+"
    r"GID=(?P<gid>\d+),\s+"
    r"home=(?P<home_dir>[^,]+)"
)


def parse_line(raw_line: str, reference_date: datetime) -> Optional[AuthLogEvent]:
    """
    Parse one Linux auth.log line.
    Returns:
        AuthLogEvent: when the line is a valid syslog entry.
        None: when the line dose not match the base syslog format.
    
    """

    raw_line = raw_line.rstrip("\n")

    base_match = BASE_SYSLOG_PATTERN.match(raw_line)
    if base_match:
        base = base_match.groupdict()
        try:
            timestamp = resolve_syslog_timestamp(
                base["month"],
                base["day"],
                base["time"],
                reference_date,
            )

        except ValueError as exc:
            logger.warning(
                "Invalid syslog timestamp: %s (%s)",
                raw_line,
                exc,
            )

            return AuthLogEvent(
                raw_line=raw_line,
                timestamp=reference_date,
                host=base["host"],
                process=base["process"],
                pid=int(base["pid"]) if base["pid"] else None,
                event_type=EventType.UNKNOWN,
                username=None,
                source_ip=None,
                port=None,
                command=None,
                target_user=None,
                uid=None,
                gid=None,
                home_dir=None,
            )

    else:
        iso_match = ISO_SYSLOG_PATTERN.match(raw_line)

        if not iso_match:
            return None

        base = iso_match.groupdict()
        try:
            timestamp = datetime.fromisoformat(base["timestamp"])

        except ValueError as exc:
            logger.warning(
                "Invalid ISO timestamp: %s (%s)",
                raw_line,
                exc,
            )

            return AuthLogEvent(
                raw_line=raw_line,
                timestamp=reference_date,
                host=base["host"],
                process=base["process"],
                pid=int(base["pid"]) if base["pid"] else None,
                event_type=EventType.UNKNOWN,
                username=None,
                source_ip=None,
                port=None,
                command=None,
                target_user=None,
                uid=None,
                gid=None,
                home_dir=None,
            )
    pid = int(base["pid"]) if base["pid"] is not None else None
    message = base["message"]

    for pattern, handler in PATTERN_REGISTRY:
        match = pattern.match(message)

        if match:
            return handler(
                base=base,
                raw_line=raw_line,
                match=match,
                timestamp=timestamp
            )

    return AuthLogEvent(
        raw_line = raw_line,
        timestamp = timestamp,
        host = base["host"],
        process = base["process"],
        pid = pid,
        event_type = EventType.UNKNOWN,
        username = None,
        source_ip = None,
        port = None,
        command=None,
        target_user=None,
        uid=None,
        gid=None,
        home_dir=None,
    )

def handle_failed_password(base, raw_line, match, timestamp):
    data = match.groupdict()

    return AuthLogEvent(
        raw_line=raw_line,
        timestamp=timestamp,
        host=base["host"],
        process=base["process"],
        pid=int(base["pid"]) if base["pid"] else None,
        event_type=EventType.SSH_FAILED_PASSWORD,
        username=data["username"],
        source_ip=data["source_ip"],
        port=int(data["port"]),
        command=None,
        target_user=None,
        uid=None,
        gid=None,
        home_dir=None,
    )

def handle_accepted_password(base, raw_line, match, timestamp):
    data = match.groupdict()

    return AuthLogEvent(
        raw_line=raw_line,
        timestamp=timestamp,
        host=base["host"],
        process=base["process"],
        pid=int(base["pid"]) if base["pid"] else None,
        event_type=EventType.SSH_ACCEPTED_PASSWORD,
        username=data["username"],
        source_ip=data["source_ip"],
        port=int(data["port"]),
        command=None,
        target_user=None,
        uid=None,
        gid=None,
        home_dir=None,
    )

def handle_invalid_user(base, raw_line, match, timestamp):
    data = match.groupdict()

    return AuthLogEvent(
        raw_line=raw_line,
        timestamp=timestamp,
        host=base["host"],
        process=base["process"],
        pid=int(base["pid"]) if base["pid"] else None,
        event_type=EventType.SSH_INVALID_USER,
        username=data["username"],
        source_ip=data["source_ip"],
        port=int(data["port"]),
        command=None,
        target_user=None,
        uid=None,
        gid=None,
        home_dir=None,
    )

def handle_sudo_command(base, raw_line, match, timestamp):
    data = match.groupdict()

    return AuthLogEvent(
        raw_line=raw_line,
        timestamp=timestamp,
        host=base["host"],
        process=base["process"],
        pid=int(base["pid"]) if base["pid"] else None,
        event_type=EventType.SUDO_COMMAND,
        username=data["user"],
        source_ip=None,
        port=None,
        command=data["command"],
        target_user=data["runas_user"],
        uid=None,
        gid=None,
        home_dir=None,
    )

def handle_sudo_auth_failure(base, raw_line, match, timestamp):
    return AuthLogEvent(
        raw_line=raw_line,
        timestamp=timestamp,
        host=base["host"],
        process=base["process"],
        pid=int(base["pid"]) if base ["pid"] else None,
        event_type=EventType.SUDO_AUTH_FAILURE,
        username=None,
        source_ip=None,
        port=None,
        command=None,
        target_user=None,
        uid=None,
        gid=None,
        home_dir=None,
    )

def handle_user_added(base, raw_line, match, timestamp):
    data = match.groupdict()

    return AuthLogEvent(
        raw_line=raw_line,
        timestamp=timestamp,
        host=base["host"],
        process=base["process"],
        pid=int(base["pid"]) if base["pid"] else None,
        event_type=EventType.USER_ADDED,
        username=data["username"],
        source_ip=None,
        port=None,
        command=None,
        target_user=None,
        uid=int(data["uid"]),
        gid=int(data["gid"]),
        home_dir=data["home_dir"],
    )

PATTERN_REGISTRY = [
    (FAILED_PASSWORD_PATTERN, handle_failed_password),
    (ACCEPTED_PASSWORD_PATTERN, handle_accepted_password),
    (INVALID_USER_PATTERN, handle_invalid_user),
    (SUDO_COMMAND_PATTERN, handle_sudo_command),
    (SUDO_AUTH_FAILURE_PATTERN, handle_sudo_auth_failure),
    (USER_ADDED_PATTERN, handle_user_added),
]

if __name__ == "__main__":

    reference_date = datetime(2026, 8, 16)

    sample_lines = [
        "Aug  6 09:15:22 ubuntu sshd[2543]: Failed password for invalid user admin from 192.168.1.15 port 51234 ssh2",
        "Aug  6 09:16:22 ubuntu sshd[2544]: Accepted password for sakol from 192.168.1.20 port 41234 ssh2",
        "Aug  6 09:17:22 ubuntu sshd[2545]: Invalid user test from 10.0.0.5 port 33333",
        "Aug  6 09:18:22 ubuntu sshd[2546]: Some unknown SSH event",

        "2026-08-16T12:47:46.043193+00:00 Sakol useradd[13106]: new user: name=day9_test, UID=1001, GID=1002, home=/home/day9_test, shell=/bin/sh, from=/dev/pts/11"
    ]

    for line in sample_lines:
        event = parse_line(line, reference_date)
        print(event)