from app.models.auth_event import EventType
from app.parsers.linux_parser import parse_line


def test_failed_password():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[2543]: "
        "Failed password for admin from 192.168.1.15 port 51234 ssh2"
    )

    event = parse_line(line)

    assert event is not None
    assert event.event_type == EventType.SSH_FAILED_PASSWORD
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.15"
    assert event.port == 51234

def test_accepted_password():
    line = (
        "Aug 6 09:15:22 ubuntu sshd[25444]: "
        "Accepted password for user1 from 192.168.1.20 port 41234 sshd2"
    )

    event = parse_line(line)

    assert event is not None
    assert event.event_type == EventType.SSH_ACCEPTED_PASSWORD
    assert event.username == "user1"
    assert event.source_ip == "192.168.1.20"
    assert event.port == 41234

def test_invalid_user():
    line = (
        "Aug 6 09:17:22 ubuntu sshd[2545]: "
        "Invalid user test from 10.0.0.5 port 33333"
    )

    event = parse_line(line)

    assert event is not None
    assert event.event_type == EventType.SSH_INVALID_USER
    assert event.username == "test"
    assert event.source_ip == "10.0.0.5"
    assert event.port == 33333

def test_garbage_line_returns_none():
    line = "this is not a valid auth log line"

    event = parse_line(line)

    assert event is None