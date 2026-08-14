from pathlib import Path
from app.parsers.linux_parser import parse_line
from app.models.auth_event import EventType


LOG_FILE = Path("data/sample_logs/auth_sample.log")

count = 0

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):

        line = line.rstrip("\n")
        event = parse_line(line)

        if event and event.event_type == EventType.SUDO_COMMAND:
            count += 1

        print("=" * 80)
        print(f"Line {line_number}")
        print("RAW:         ", line)
        print("EVENT TYPE:  ", event.event_type)
        print("USERNAME:    ", event.username)
        print("TARGET USER: ", event.target_user)
        print("COMMAND:     ", event.command)

        if count == 5:
            break