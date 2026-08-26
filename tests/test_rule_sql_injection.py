"""Dedicated tests for Rule 6: SQL injection detection."""

from datetime import datetime, timezone

from app.detection.rules.sql_injection import SQLInjectionRule
from app.models.normalized_event import NormalizedEvent
from app.detection.engine import DetectionEngine


BASE_TIME = datetime(2026, 8, 26, 15, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    path: str,
    query_string: str,
    source_type: str = "access",
    event_type: str = "access",
) -> NormalizedEvent:
    """Create a normalized access event for testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=BASE_TIME,
        source_type=source_type,
        source_ip="10.0.0.5",
        username=None,
        raw_event_type=event_type,
        raw_data={
            "path": path,
            "query_string": query_string,
            "status_code": 200,
        },
    )

def test_boolean_based_sqli_in_query_triggers():
    """A recognizable boolean SQLI payload should trigger."""

    events = [
        make_event(
            "1",
            "/search",
            "q=' OR 1=1 --",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "sql_injection"
    assert alerts[0].event.event_id == "1"

def test_union_select_sqli_triggers():
    """A UNION SELECT payload should trigger."""

    events = [
        make_event(
            "1",
            "/product",
            "id=1 UNION SELECT username,password FROM users"
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_sqli_in_path_triggers():
    """A SQLI signature in the path should trigger."""

    events = [
        make_event(
            "1",
            "/products/1 UNION SELECT password FROM users",
            "",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "sql_injection"

def test_normal_request_does_not_trigger():
    """A normal web request should not trigger."""

    events = [
        make_event(
            "1",
            "/products",
            "id=123&category=books",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert alerts == []

def test_non_access_event_is_ignored():
    """Non-access events should be ignored."""

    events = [
        make_event(
            "1",
            "/search",
            "q=' OR 1=1 --",
            source_type="auth",
            event_type="ssh_failed_password",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert alerts == []

def test_url_encoded_boolean_sqli_is_not_currently_detected():
    """URL-encoded SQLi is a documented current limitation."""

    events = [
        make_event(
            "1",
            "/search",
            "q=%27%20OR%201%3D1",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert alerts == []

def test_only_matching_events_generate_alerts():
    """Only events containing SQLi signatures should generate alerts."""

    events = [
        make_event(
            "malicious",
            "/search",
            "q=' OR 1=1 --",
        ),
        make_event(
            "normal",
            "/products",
            "id=123",
        ),
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event.event_id == "malicious"

def test_engine_runs_sql_injection_rule():
    """DetectionEngine should execute Rule 6."""

    events = [
        make_event(
            "malicious",
            "/search",
            "q=' OR 1=1 --",
        )
    ]

    engine = DetectionEngine()
    engine.register_rule(SQLInjectionRule())

    alerts = engine.run(events)

    assert len(alerts) == 1
    assert alerts[0].rule_name == "sql_injection"
    assert alerts[0].event.event_id == "malicious"

def test_select_from_signature():
    """SELECT ... FROM pattern should trigger."""

    events = [
        make_event(
            "select-from",
            "/search",
            "q=SELECT username FROM users",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_insert_into_signature():
    """INSERT INTO pattern should trigger."""

    events = [
        make_event(
            "insert",
            "/api",
            "q=INSERT INTO users VALUES (1)",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

def test_update_set_signature():
    """UPDATE ... SET pattern should trigger."""

    events = [
        make_event(
            "update",
            "/api",
            "q=UPDATE users SET passowrd='x'",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_delete_from_signature():
    """DELETE FROM pattern should trigger."""

    events = [
        make_event(
            "delete",
            "/api",
            "q=DELETE FROM users WHERE id=1",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_drop_table_signature():
    """DROP TABLE pattern should trigger."""

    events = [
        make_event(
            "drop",
            "/api",
            "q=DROP TABLE users",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_sql_comment_signature():
    """SQL double-dash comment pattern should trigger."""

    events = [
        make_event(
            "comment",
            "/search",
            "q=admin' --",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_block_comment_signature():
    """SQL block comment pattern should trigger."""

    events = [
        make_event(
            "block-comment",
            "/search",
            "q=admin' /* comment */",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_having_signature():
    """HAVING 1=1 pattern should trigger."""

    events = [
        make_event(
            "having",
            "/search",
            "q=HAVING 1=1",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_sleep_signature():
    """SLEEP function pattern should trigger."""

    events = [
        make_event(
            "sleep",
            "/search",
            "q=SLEEP(5)",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_stacked_query_signature():
    """Stacked SQL query pattern should trigger."""

    events = [
        make_event(
            "stacked",
            "/search",
            "q=1; SELECT username FROM users",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_string_boolean_signature():
    """String-based boolean SQLi pattern should trigger."""

    events = [
        make_event(
            "string-boolean",
            "/search",
            "q=' OR 'a'='a'",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert len(alerts) == 1

def test_hash_comment_signature():
    """SQL hash-comment pattern should trigger."""

    events = [
        make_event(
            "hash-coment",
            "/search",
            "q=admin' #",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

def test_sql_looking_but_benign_request_does_not_trigger():
    """SQL-looking natural language should not trigger."""

    events = [
        make_event(
            "benign",
            "/search",
            "q=select a book about databases",
        )
    ]

    alerts = SQLInjectionRule().evaluate(events)

    assert alerts == []