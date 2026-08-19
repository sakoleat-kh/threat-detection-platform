"""Command-line interdace for streaming Linux auth logs."""

import argparse
from collections import Counter
from datetime import datetime

from app.parsers.auth_log_reader import read_auth_log

def main():
    parser = argparse.ArgumentParser(
        description="Read and summarize a Linux auth.log file."
    )

    parser.add_argument(
        "file_path",
        help="Path to the auth.log file",
    )

    args = parser.parse_args()

    reference_date = datetime.now()

    counts = Counter()

    for index, event in enumerate(
        read_auth_log(args.file_path, reference_date),
        start=1,
    ):
        counts[event.event_type] += 1

        if index <= 10:
            print(event)



    print("\nEvent Summary")
    print("---------------")

    for event_type, count in counts.items():
        print(f"{event_type.value:<25} {count}")

if __name__ == "__main__":
    main()