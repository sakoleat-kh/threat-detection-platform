"""Tests for security event normalization"""

from datetime import datetime, timezone

from app.models.access_event import AccessLogEvent
from app.models.auth_event import AuthLogEvent, EventType
from app.models.normalized_event import NormalizedEvent
from app.services.normalizer import (normalize_auth_event, normalize_access_event)

def test_normalize_auth_event():
    event = AuthLogEvent(
        raw_line="test auth event",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        host="test_host",
        process="sshd",
        pid=123,
        event_type=EventType.SUDO_COMMAND,
        username="ubuntu",
        source_ip="192.168.1.10",
        port=None,
        command="/usr/bin/id",
        target_user="root",
        uid=None,
        gid=None,
        home_dir=None,
    )
    normalized = normalize_auth_event(event)

    assert isinstance(normalized, NormalizedEvent)
    assert normalized.source_type == "auth"
    assert normalized.source_ip == "192.168.1.10"
    assert normalized.username == "ubuntu"
    assert normalized.raw_data["command"] == "/usr/bin/id"
    assert normalized.raw_data["target_user"] == "root"

def test_normalize_unknown_auth_event():
    event = AuthLogEvent(
        raw_line="unknown event",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
        host="test-host",
        process="sshd",
        pid=123,
        event_type=EventType.UNKNOWN,
        username=None,
        source_ip=None,
        port=None,
        command=None,
        target_user=None,
        uid=None,
        gid=None,
        home_dir=None,
    )

    normalized = normalize_auth_event(event)

    assert normalized.source_type == "auth"
    assert normalized.source_ip is None
    assert normalized.username is None
    assert normalized.raw_event_type == "unknown"

def test_normalize_access_event():
    event = AccessLogEvent(
        client_ip="192.168.1.20",
        remote_logname="-",
        authenticated_user="-",
        timestamp=datetime.now(timezone.utc),
        request="GET /index.html HTTP/1.1",
        method="GET",
        path="/index.html",
        query_string="",
        protocol="HTTP/1.1",
        status_code=200,
        response_size=1234,
        referer="-",
        user_agent="Mozilla/5.0",
    )

    normalized = normalize_access_event(event)

    assert isinstance(normalized, NormalizedEvent)
    assert normalized.source_type == "access"
    assert normalized.source_ip == "192.168.1.20"
    assert normalized.username is None
    assert normalized.raw_event_type == "access"
    assert normalized.raw_data["method"] == "GET"
    assert normalized.raw_data["path"] == "/index.html"
    assert normalized.raw_data["status_code"] == 200
    assert normalized.raw_data["user_agent"] == "Mozilla/5.0"

def test_normalize_access_query_string():
    event = AccessLogEvent(
        client_ip="10.0.0.5",
        remote_logname="-",
        authenticated_user="-",
        timestamp=datetime.now(timezone.utc),
        request="GET /search?q=test HTTP/1.1",
        method="GET",
        path="/search",
        query_string="q=test",
        protocol="HTTP/1.1",
        status_code=200,
        response_size=500,
        referer="-",
        user_agent="Mozilla/5.0"
    )

    normalized = normalize_access_event(event)

    assert normalized.raw_data["path"] == "/search"
    assert normalized.raw_data["query_string"] == "q=test"

def test_normalize_access_sqli_payload():
    event = AccessLogEvent(
        client_ip="10.0.0.5",
        remote_logname="-",
        authenticated_user="-",
        timestamp=datetime.now(timezone.utc),
        request="GET /search?q=' OR 1=1-- HTTP/1.1",
        method="GET",
        path="/search",
        query_string="q=' OR 1=1--",
        protocol="HTTP/1.1",
        status_code=200,
        response_size=1234,
        referer="-",
        user_agent="Mozilla/5.0",
    )

    normalized = normalize_access_event(event)

    assert normalized.raw_data["query_string"] == "q=' OR 1=1--"