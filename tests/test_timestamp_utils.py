from datetime import datetime

import pytest

from app.parsers.timestamp_utils import resolve_syslog_timestamp


def test_resolve_syslog_timestamp_older_than_six_months_stays_in_same_year():
    """An old log line must not be pushed into the future."""
    result = resolve_syslog_timestamp(
        month="Jan",
        day="10",
        time_str="12:30:00",
        reference_date=datetime(2026, 8, 16),  # noqa: DTZ001
    )

    assert result == datetime(2026, 1, 10, 12, 30, 0)  # noqa: DTZ001


def test_resolve_syslog_timestamp_previous_year():
    """A December line read in early January belongs to the previous year."""
    result = resolve_syslog_timestamp(
        month="Dec",
        day="31",
        time_str="23:30:00",
        reference_date=datetime(2027, 1, 2),  # noqa: DTZ001
    )

    assert result == datetime(2026, 12, 31, 23, 30, 0)  # noqa: DTZ001


def test_resolve_syslog_timestamp_march_with_october_reference():
    """Regression: the alert that showed 2027-03-30 must resolve to 2026."""
    result = resolve_syslog_timestamp(
        month="Mar",
        day="30",
        time_str="16:01:20",
        reference_date=datetime(2026, 10, 7),  # noqa: DTZ001
    )

    assert result == datetime(2026, 3, 30, 16, 1, 20)  # noqa: DTZ001


def test_resolve_syslog_timestamp_never_in_the_future():
    """The result must not be later than the reference date (plus tolerance)."""
    reference = datetime(2026, 10, 7)  # noqa: DTZ001
    result = resolve_syslog_timestamp("Nov", "15", "08:00:00", reference)

    assert result == datetime(2025, 11, 15, 8, 0, 0)  # noqa: DTZ001


def test_resolve_syslog_timestamp_leap_day():
    """Feb 29 skips non-leap years and finds the latest leap year."""
    result = resolve_syslog_timestamp(
        month="Feb",
        day="29",
        time_str="10:00:00",
        reference_date=datetime(2026, 3, 1),  # noqa: DTZ001
    )

    assert result == datetime(2024, 2, 29, 10, 0, 0)  # noqa: DTZ001


def test_resolve_syslog_timestamp_invalid_date_raises():
    with pytest.raises(ValueError):
        resolve_syslog_timestamp(
            month="Feb",
            day="30",
            time_str="10:00:00",
            reference_date=datetime(2026, 3, 1),  # noqa: DTZ001
        )