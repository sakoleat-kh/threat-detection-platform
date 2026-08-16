# Syslog Timestamp Design

Traditional syslog timestamps contain the month, day, and time, but not the year.

For example:
    Dec 31 23:30:00

The missing year creates a year-rollover problem. If the reference data is 2027-01-02, the timestamp above should resolve to:
    2026-12-31 23:30:00

The parser therefore uses a reference data to datermine the most appropriate year for the syslog timestamp.

The goal is to convert:
    month + day + time + reference data

into a complete Python datetime object with the correct year.