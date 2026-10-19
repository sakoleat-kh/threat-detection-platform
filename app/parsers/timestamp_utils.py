"""Resolve Linux syslog timestamps into year-aware datetime objects."""

from datetime import datetime, timedelta


def resolve_syslog_timestamp(
    month: str,
    day: str,
    time_str: str,
    reference_date: datetime,
) -> datetime:
    """
    Resolve a traditional syslog timestamp that does not contain a year.

    Log events always happened in the past, so the result is the most recent
    date matching the month/day/time that is not after reference_date.

    Example:
        month="Dec", day="31", time_str="23:30:00",
        reference_date=datetime(2027, 1, 2)
        returns datetime(2026, 12, 31, 23, 30, 0)

        month="Mar", day="30", time_str="16:01:20",
        reference_date=datetime(2026, 10, 7)
        returns datetime(2026, 3, 30, 16, 1, 20)
    """
    month_number = datetime.strptime(month, "%b").month  # noqa: DTZ007
    hour, minute, second = (
        int(time_str[0:2]),
        int(time_str[3:5]),
        int(time_str[6:8]),
    )

    # Allow a small tolerance for clock differences between server and logger.
    latest_allowed = reference_date + timedelta(days=1)

    for year in (reference_date.year, reference_date.year - 1, reference_date.year - 2):
        try:
            candidate = datetime(  # noqa: DTZ001
                year, month_number, int(day), hour, minute, second
            )
        except ValueError:  # e.g. Feb 29 in a non-leap year
            continue
        if candidate <= latest_allowed:
            return candidate

    raise ValueError(f"Cannot resolve timestamp: {month} {day} {time_str}")