from datetime import datetime, timezone

from app.models.auth_event import EventType
from app.parsers.linux_parser import parse_line

REFERENCE_DATE = datetime(2026, 8, 16)

def test_failed_password():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[2543]: "
        "Failed password for admin from 192.168.1.15 port 51234 ssh2"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.SSH_FAILED_PASSWORD
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.15"
    assert event.port == 51234
    assert event.timestamp == datetime(2026, 8, 6, 9, 15, 22)


def test_accepted_password():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[25444]: "
        "Accepted password for user1 from 192.168.1.20 port 41234 sshd2"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.SSH_ACCEPTED_PASSWORD
    assert event.username == "user1"
    assert event.source_ip == "192.168.1.20"
    assert event.port == 41234
    assert event.timestamp == datetime(2026, 8, 6, 9, 15, 22)

def test_invalid_user():
    line = (
        "Aug 6 09:17:22 ubuntu sshd[2545]: "
        "Invalid user test from 10.0.0.5 port 33333"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.SSH_INVALID_USER
    assert event.username == "test"
    assert event.source_ip == "10.0.0.5"
    assert event.port == 33333
    assert event.timestamp == datetime(2026, 8, 6, 9, 17, 22)


def test_garbage_line_returns_none():
    line = "this is not a valid auth log line"

    event = parse_line(line, REFERENCE_DATE)

    assert event is None


def test_user_added():
    line = (
        "2026-08-16T12:47:46.043193+00:00 Sakol "
        "useradd[13106]: new user: name=day9_test, UID=1001, "
        "GID=1002, home=/home/day9_test, shell=/bin/sh, from=/dev/pts/11"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.USER_ADDED
    assert event.username == "day9_test"
    assert event.uid == 1001
    assert event.gid == 1002
    assert event.home_dir == "/home/day9_test"
    assert event.timestamp == datetime(2026, 8, 16, 12, 47, 46, 43193, tzinfo=timezone.utc)

def test_december_january_year_rollover():
    line = (
        "Dec 31 23:30:00 ubuntu sshd[9999]: "
        "Failed password for admin from 192.168.1.50 port 55555 ssh2"
    )
    reference_date = datetime(2027, 1, 2)

    event = parse_line(line, reference_date)

    assert event is not None
    assert event.event_type == EventType.SSH_FAILED_PASSWORD
    assert event.timestamp == datetime(2026, 12, 31, 23, 30, 0)

def test_sudo_command():
    line = (
        "Aug 6 09:20:00 ubuntu sudo: "
        "sakol : TTY=pts/0 ; PWD=/home/sakol ; "
        "USER=root ; COMMAND=/usr/bin/whoami"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.SUDO_COMMAND
    assert event.username == "sakol"
    assert event.target_user == "root"
    assert event.command == "/usr/bin/whoami"

def test_sudo_auth_failure():
    line = (
        "Aug 6 09:21:00 ubuntu sudo: "
        "pam_unix(sudo:auth): authentication failure"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type == EventType.SUDO_AUTH_FAILURE

def test_unknown_event():
    line = (
        "Aug 6 09:22:00 ubuntu sshd[9999]: "
        "Some completely unknown SSH event"
    )

    event = parse_line(line, REFERENCE_DATE)

    assert event is not None
    assert event.event_type ==  EventType.UNKNOWN