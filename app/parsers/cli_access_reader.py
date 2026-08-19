"""Comand-line interface for streaming Apache access logs."""

import argparse
from collections import Counter

from app.parsers.access_log_reader import read_access_log

def main():
    parser = argparse.ArgumentParser(
        description="Read and summarize an Apache access.log file."
    )

    parser.add_argument(
        "file_path",
        help="Path to the Apache access.log file",
    )

    args = parser.parse_args()

    counts = Counter()

    for index, event in enumerate(read_access_log(args.file_path),start=1):
        counts[event.status_code] += 1

        if index < 10:
            print(event)

        print("\nHTTP Status Summary")
        print("---------------------")

        for status_code, count in sorted (counts.items()):
            print(f"{status_code:<25} {count}")

if __name__ == "__main__":
    main()