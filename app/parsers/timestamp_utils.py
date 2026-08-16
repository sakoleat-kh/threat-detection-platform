from datetime import datetime, timedelta

def resolve_syslog_timestamp(
    month: str,
    day: str,
    time_str: str,
    reference_date: datetime,
) -> datetime:
    """
    Resolve a traditional syslog timestamp that does not contaion a year.

    Example:
        month="Dec"
        day="31"
        time_str="23:30:00"
        reference_date=datetime(2027, 1, 2)

    returns:
        datetime(2026, 12, 31, 23, 30, 0)
    
    """

    month_number = datetime.strptime(month, "%b").month

    candidate = datetime(
        year=reference_date.year,
        month=month_number,
        day=int(day),
        hour=int(time_str[0:2]),
        minute=int(time_str[3:5]),
        second=int(time_str[6:8]),
    )

    # If the candidate is more than 6 months in the future
    # relative to the reference date, treat it as the previous year.
    if candidate - reference_date > timedelta(days=183):
        candidate = candidate.replace(year=candidate.year - 1)

    # If the candidate is more than 6 month in the past,
    # treat it as the following year.
    elif reference_date - candidate > timedelta(days=183):
        candidate = candidate.replace(year=candidate.year + 1)

    return candidate

if __name__ == "__main__":
    reference = datetime(2027, 1, 2)

    test_cases = [
        ("Aug", "6", "09:15:22"),
        ("Jan", "10", "12:00:00"),
        ("Dec", "31", "23:30:00"),
        ("Jan", "1", "00:05:00"),
        ("Jul", "15", "18:20:30"),
    ]

    for month, day, time_str in test_cases:
        result = resolve_syslog_timestamp(
            month,
            day,
            time_str,
            reference,
        )

        print(
            f"{month} {day} {time_str}"
            f" -> {result}"
        )