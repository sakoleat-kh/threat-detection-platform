from app.parsers.apache_parser import parse_access_line

def test_normal_get_request():
    line = (
        '54.36.149.41 - - '
        '[22/Jan/2019:03:56:14 +0330] '
        '"GET /index.html HTTP/1.1" '
        '200 1543 "-" "Mozilla/5.0" "-"' 
    )

    event = parse_access_line(line)

    assert event is not None
    assert event.client_ip == "54.36.149.41"
    assert event.method == "GET"
    assert event.path == "/index.html"
    assert event.query_string == ""
    assert event.protocol == "HTTP/1.1"
    assert event.status_code == 200
    assert event.response_size == 1543
    assert event.referer == "-"
    assert event.user_agent == "Mozilla/5.0"

def test_request_with_query_string():
    line = (
        '66.249.66.91 - - '
        '[22/Jan/2019:03:56:20 +0330] '
        '"GET /filter/products?page=4 HTTP/1.1" '
        '200 39660 "-" "Mozilla/5.0" "-"'
    )

    event = parse_access_line(line)

    assert event is not None
    assert event.path == "/filter/products"
    assert event.query_string == "page=4"
    assert event.method == "GET"
    assert event.protocol == "HTTP/1.1"

def test_aqli_style_payload_in_path():
    line = (
        '192.168.1.10 - - '
        '[22/Jan/2019:03:56:21 +0330] '
        '''"GET /search?id=1%27%20OR%201%3D1 HTTP/1.1" '''
        '200 1234 "-" "Mozilla/5.0" "-"'
    )

    event = parse_access_line(line)

    assert event is not None
    assert event.path == "/search"
    assert event.query_string == "id=1%27%20OR%201%3D1"

def test_xss_style_payload():
    line = (
        '192.168.1.20 - - '
        '[22/Jan/2019:03:56:22 +0330] '
        '''"GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1" '''
        '200 1234 "-" "Mozilla/5.0" "-"'
    )

    event = parse_access_line(line)

    assert event is not None
    assert event.path == "/search"
    assert event.query_string == ("q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")

def test_garbage_line_returns_none():
    line = "this is completely invalid apache log data"

    event = parse_access_line(line)

    assert event is None

def test_missing_referre_and_user_agent():
    line = (
        '54.36.149.41 - - '
        '[22/Jan/2019:03:56:14 +0330] '
        '"GET /index.html HTTP/1.1" '
        '200 1543'
    )

    event = parse_access_line(line)

    assert event is None