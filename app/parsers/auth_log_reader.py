from datetime import datetime
from pathlib import Path
from typing import Iterator

from app.models.auth_event import AuthLogEvent
from app.parsers.linux_parser import parse_line

def read_auth_log(
    file_path: str | Path,
    reference_date: datetime,
) -> Iterator[AuthLogEvent]:
    """Read an auth.log file and yield parsed events one at a time."""

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            event = parse_line(line, reference_date)

            if event is not None:
                yield event