from datetime import datetime

from app.parsers.timestamp_utils import resolve_syslog_timestamp


def test_resolve_syslog_timestamp_following_year():
    """A timestamp more than 6 months before the reference date rolls forward one year."""

    result = resolve_syslog_timestamp(
        month="Jan",
        day="10",
        time_str="12:30:00",
        reference_date=datetime(2026, 8, 16),
    )

    assert result == datetime(2027, 1, 10, 12, 30, 0)
