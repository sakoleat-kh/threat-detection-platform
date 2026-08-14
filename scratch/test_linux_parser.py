from pathlib import Path

from app.parsers.linux_parser import parse_line

LOG_FILE = Path("data/sample_logs/auth_sample.log")

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):
        if line_number > 20:
            break
        event = parse_line(line)

        print("=" * 80)
        print(f"\nLine {line_number}")
        print("RAW:   ", line)
        print("PARSED:", event)