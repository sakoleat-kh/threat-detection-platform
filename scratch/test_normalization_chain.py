"""Sanity-check the full log parsing and normalization chain."""

from datetime import datetime

from app.parsers.apache_parser import parse_access_line
from app.parsers.auth_log_reader import read_auth_log
from app.services.normalizer import (
    normalize_access_event,
    normalize_auth_event,)

def check_auth():
    """Parse and normalize the first 10 auth events."""
    print("=== AUTH LOG CHAIN ===")

    events = list(
        read_auth_log(
            "data/sample_logs/auth_sample.log",
            datetime.now(),
        )
    )

    for index, event in enumerate(events[:10], start=1):
        normalized = normalize_auth_event(event)

        print(f"\n--- Auth Event {index} ---")
        print("Parsed:", event)
        print("Normalized:", normalized)

def check_access():
    """Parse and noralize the first 10 Apache access events."""
    print("\n=== ACCESS LOG CHAIN ===")

    with open(
        "data/sample_logs/access_sample.log",
        "r",
        encoding="utf-8",
    ) as file:
        for index, line in enumerate(file, start=1):
            if index > 10:
                break

            event = parse_access_line(line)

            print(f"\n--- Access Event {index} ---")

            if event is None:
                print("Parsed: None")
                print("Normalized: None")
                continue

            normalized = normalize_access_event(event)

            print("Parsed:", event)
            print("Normalized:", normalized)

if __name__ == "__main__":
    check_auth()
    check_access()