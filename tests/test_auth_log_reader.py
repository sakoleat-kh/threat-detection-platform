from datetime import datetime

from app.models.auth_event import EventType
from app.parsers.auth_log_reader import read_auth_log


def test_reader_skips_blank_lines(tmp_path):
    """Auth log reader should ignore blank lines."""

    log_file = tmp_path / "blank_lines.log"

    log_file.write_text(
        "\n"
        "   \n"
        "Aug 6 09:15:22 ubuntu sshd[2543]: "
        "Failed password for admin from 192.168.1.15 port 51234 ssh2\n",
        encoding="utf-8",
    )

    events = list(
        read_auth_log(
            log_file,
            datetime(2026, 8, 16),
        )
    )

    assert len(events) == 1
    assert events[0].event_type == EventType.SSH_FAILED_PASSWORD
    assert events[0].username == "admin"
