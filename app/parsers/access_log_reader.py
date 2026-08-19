"""Stream and parse Apache access.log files into structured events."""

import logging

from pathlib import Path
from typing import Iterator

from app.models.access_event import AccessLogEvent
from app.parsers.apache_parser import parse_access_line

logger = logging.getLogger(__name__)

def read_access_log(
    file_path: str | Path,
) -> Iterator[AccessLogEvent]:
    """Read an Apache access.log file and yield parsed events one at a time."""

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                event = parse_access_line(line)
            except ValueError as exc:
                logger.warning(
                    "Skipping malformed access-log line: %s (%s)",
                    line,
                    exc,
                )
                continue

            if event is not None:
                yield event