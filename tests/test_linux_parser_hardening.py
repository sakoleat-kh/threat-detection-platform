from datetime import datetime

from app.models.auth_event import EventType
from app.parsers.linux_parser import parse_line

REFERENCE_DATE = datetime(2026, 8, 17)

def test_invalid_syslog_timestamp_returns_unknown():
    line = (
        "Aug 99 99:99:99 ubuntu sshd[1234]: "
        "Failed password for admin from 192.168.1.10 port 22"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.UNKNOWN

def test_invalid_iso_timestamp_returns_unknown():
    line = (
        "2026-99-99T99:99:99+00:00 ubuntu sshd[1234]: "
        "Failed password for admin from 192.168.1.10 port 22"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.UNKNOWN

def test_malformed_failed_password_returns_unknown():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[1234]: "
        "Failed password for 192.168.1.10 port abc"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.UNKNOWN

def test_malformed_accepted_password_returns_unknown():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[1234]: "
        "Accepted password for admin from port 22"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.UNKNOWN

def test_malformed_user_added_returns_unknown():
    line = (
        "2026-08-16T12:47:46+00:00 ubuntu useradd[1234]: "
        "new user: name=alice, UID=abc, GID=1001, home=/home/alice"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.UNKNOWN

def test_missinf_ssh_username_returns_unknown():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[1234]: "
        "Failed password for from 192.168.1.10 port 22"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.UNKNOWN

def test_incomplete_syslog_line_returns_none():
    line = "Aug 6 09:15:22"

    event = parse_line(line, REFERENCE_DATE)

    assert event is None

def test_completely_garbage_line_returns_none():
    line = "this is completely garbage"

    event = parse_line(line, REFERENCE_DATE)

    assert event is None

def test_malformed_pid_returns_none():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[abc]: "
        "Failed password for admin from 192.168.1.10 port 22"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is None

def test_incomplete_auth_log_line_returns_none():
    line = "Aug 6 09:15:22"

    event = parse_line(line, REFERENCE_DATE)

    assert event is None