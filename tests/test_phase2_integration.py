"""Phase 2 integration test for all eight detection rules."""

from datetime import datetime, timedelta, timezone

from app.detection.engine import DetectionEngine
from app.detection.rules.directory_scanning import DirectoryScanningRule
from app.detection.rules.excessive_sudo import ExcessiveSudoRule
from app.detection.rules.new_user_creation import NewUserCreationRule
from app.detection.rules.sql_injection import SQLInjectionRule
from app.detection.rules.suspicious_user_agent import SuspiciousUserAgentRule
from app.detection.rules.xss_attempt import XSSAttemptRule
from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.detection.rules.successful_after_failures import SuccessfulAfterFailuresRule
from app.models.normalized_event import NormalizedEvent

BASE_TIME = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)

def make_event(
    event_id: str,
    timestamp: datetime,
    source_type: str,
    source_ip: str | None,
    username: str | None,
    raw_event_type: str,
    raw_data: dict,
) -> NormalizedEvent:
    """Create a normalized event for integration testing."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type=source_type,
        source_ip=source_ip,
        username=username,
        raw_event_type=raw_event_type,
        raw_data=raw_data,
    )

def build_phase2_events() -> list[NormalizedEvent]:
    """Build synthetic events covering all eight rule."""
    events = []

    # Rule 1 + Rule 2:
    # Five failed SSH logins followed by one successful login.
    for i in range(5):
        events.append(
            make_event(
                f"failed-{i}",
                BASE_TIME + timedelta(seconds=i * 20),
                "auth",
                "10.0.0.10",
                "admin",
                "ssh_failed_password",
                {},
            )
        )

    events.append(
        make_event(
            "ssh_success",
            BASE_TIME + timedelta(seconds=120),
            "auth",
            "10.0.0.10",
            "admin",
            "ssh_accepted_password",
            {},
        )
    )

        # Rule 3: excessive sudo usage.
    for i in range(10):
        events.append(
            make_event(
                f"sudo-{i}",
                BASE_TIME + timedelta(seconds=i * 20),
                "auth",
                None,
                "ubuntu",
                "sudo_command",
                {},
            )
        )

        # Rule 4: new user creation
    events.append(
        make_event(
            "new-user",
            BASE_TIME,
            "auth",
            None,
            "alice",
            "user_added",
            {"uid": 1001},
        )
    )

        # Rule 5: directory scanning
    for i in range(15):
        events.append(
            make_event(
                f"scan-{i}",
                BASE_TIME + timedelta(seconds=i * 10),
                "access",
                "10.0.0.20",
                None,
                "access",
                {
                    "path": f"/scan-{i}",
                    "status_code": 404,
                },
            )
        )

        # Rule 6: SQL iniection
    events.append(
        make_event(
            "sqli",
            BASE_TIME,
            "access",
            "10.0.0.30",
            None,
            "access",
            {
                "path": "/search",
                "query_string": "q=' OR 1=1 --",
                "status_code": 200,
            },
        )
    )

        # Rule 7: XSS
    events.append(
        make_event(
            "xxs",
            BASE_TIME,
            "access",
            "10.0.0.31",
            None,
            "access",
            {
                "path": "/search",
                "query_string": "q=<script>alert(1)</script>",
                "status_code": 200,
            },
        )
    )

    # Rule 8: suspicious User-Agent
    events.append(
        make_event(
            "suspicious-ua",
            BASE_TIME,
            "access",
            "10.0.0.32",
            None,
            "access",
            {
                "path": "/",
                "query_string": "",
                "user_agent": "sqlmap/1.8",
                "status_code": 200,
            },
        )
    )

    return events

def test_phase2_all_eight_rules_work_together():
    """All eight Phase 2 rules should generate expected alerts."""

    engine = DetectionEngine()

    # Register all eight Phase 2 rules.
    engine.register_rule(SSHBruteForceRule())
    engine.register_rule(SuccessfulAfterFailuresRule())
    engine.register_rule(ExcessiveSudoRule())
    engine.register_rule(NewUserCreationRule())
    engine.register_rule(DirectoryScanningRule())
    engine.register_rule(SQLInjectionRule())
    engine.register_rule(XSSAttemptRule())
    engine.register_rule(SuspiciousUserAgentRule())

    alerts= engine.run(build_phase2_events())

    rule_names = {alert.rule_name for alert in alerts}

    expected_rules = {
        "ssh_brute_force",
        "successful_after_failures",
        "excessive_sudo",
        "new_user_creation",
        "directory_scanning",
        "sql_injection",
        "xss_attempt",
        "suspicious_user_agent",
    }

    assert expected_rules.issubset(rule_names)