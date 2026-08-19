from app.parsers.apache_parser import parse_access_line
from app.parsers.access_log_reader import read_access_log

def test_garbage_line_returns_none():
    event = parse_access_line("this is completely garbage")

    assert event is None

def test_invalid_timestamp_returns_value_error():
    line = (
        '192.168.1.10 - - '
        '[bad timestamp] '
        '"GET / HTTP/1.1" '
        '200 123 "-" "Mozilla/5.0" "-"'
    )

    try:
        parse_access_line(line)
    except ValueError:
        pass
    else:
        raise AssertionError("Exception ValueError for invalid timestamp")

def test_invalid_time_returns_value_error():
    line = (
        '192.168.1.10 - - '
        '[22/Jan/2019:99:99:99 +0330] '
        '"GET / HTTP/1.1" '
        '200 123 "-" "Mozilla/5.0" "-"'
    )
    try:
        parse_access_line(line)
    except ValueError:
        pass
    else:
        raise AssertionError("Expect ValueError for invalid time")

def test_reader_skip_malformed_lines(tmp_path):
    log_file = tmp_path / "malformed.log"

    log_file.write_text(
        'this is garbage\n'
        '192.168.1.10 - - [bad timestamp] "GET / HTTP/1.1" '
        '200 123 "-" "Mozilla/50" "-"\n'
        '54.36.149.41 - - [22/Jan/2019:03:56:14 +0330] '
        '"GET /index.html HTTP/1.1" 200 1543 "-" "Mozilla/5.0" "-"\n',
        encoding="utf-8",
    )

    events = list(read_access_log(log_file))

    assert len(events) == 1
    assert events[0].path == "/index.html"

def test_malformed_status_code_returns_none():
    line = (
        '192.168.1.10 - - '
        '[22/Jan/2019:03:56:14 +0330] '
        '"GET / HTTP/1.1" abc 123 "-" "Mozilla/5.0" "-"'
    )

    assert parse_access_line(line) is None

def test_malformed_response_size_returns_none():
    line = (
        '192.168.1.10 - - '
        '[22/Jan/2019:03:56:14 +0330] '
        '"GET / HTTP/1.1" 200 abc "-" "Mozilla/5.0" "-"'
    )

    assert parse_access_line(line) is None

def test_incomplete_access_line_returns_none():
    line = (
        '192.168.1.10 - - '
        '[22/Jan/2019:03:56:14 +0330] '
        '"GET / HTTP/1.1" 200 123'
    )

    assert parse_access_line(line) is None

def test_broken_request_returns_none():
    line = (
        '192.168.1.10 - - '
        '[22/Jan/2019:-3:56:14 +0330] '
        '"BROKEN REQUEST" 200 123 "-" "Mozilla/5.0" "-"'
    )

    assert parse_access_line(line) is None