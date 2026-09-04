"""Tests for alert repository filtering and pagination."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.models.database import Base
from app.models.db_alert import AlertRecord
from app.repository.alert_repository import get_alerts_filtered

@pytest.fixture
def session():
    """Provide an isolated in-memory SQLite session for each test."""

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    with Session(engine) as session:
        yield session
    engine.dispose()

@pytest.fixture
def seeded_alerts(session):
    """Seed the test database with varied alerts."""

    now = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)

    alerts = [
        AlertRecord(
            rule_id="ssh_brute_force",
            rule_name="ssh_brute_force",
            severity="high",
            description="SSh brute force",
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            source_type="auth",
            source_ip="10.0.0.1",
            username="admin",
            event_timestamp=now - timedelta(days=10),
            created_at=now - timedelta(days=10),
            raw_event_json={"test": 1},
        ),
        AlertRecord(
            rule_id="ssh_brute_force",
            rule_name="ssh_brute_force",
            severity="high",
            description="SSH brute force",
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            source_type="auth",
            source_ip="10.0.0.2",
            username="root",
            event_timestamp=now - timedelta(days=8),
            created_at=now - timedelta(days=8),
            raw_event_json={"test": 2},
        ),
        AlertRecord(
            rule_id="sql_injection",
            rule_name="sql_injection",
            severity="high",
            description="SQl injection",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            source_type="access",
            source_ip="10.0.0.3",
            username=None,
            event_timestamp=now - timedelta(days=6),
            created_at=now - timedelta(days=6),
            raw_event_json={"test": 3},
        ),
        AlertRecord(
            rule_id="sql_injection",
            rule_name="sql_injection",
            severity="medium",
            description="SQl injection",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            source_type="access",
            source_ip="10.0.0.3",
            username=None,
            event_timestamp=now - timedelta(days=4),
            created_at=now - timedelta(days=4),
            raw_event_json={"test": 4},
        ),
        AlertRecord(
            rule_id="xss_attempt",
            rule_name="xss_attempt",
            severity="medium",
            description="XSS attempt",
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic="Initial Access",
            source_type="access",
            source_ip="10.0.0.5",
            username=None,
            event_timestamp=now - timedelta(days=2),
            created_at=now - timedelta(days=2),
            raw_event_json={"test": 5},
        ),
        AlertRecord(
            rule_id="directory_scanning",
            rule_name="directory_scanning",
            severity="low",
            description="Directory scanning",
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            tactic="Discovery",
            source_type="access",
            source_ip="10.0.0.6",
            username=None,
            event_timestamp=now - timedelta(days=1),
            created_at=now - timedelta(days=1),
            raw_event_json={"test": 6},
        ),
        AlertRecord(
            rule_id="new_user_creation",
            rule_name="new_user_creation",
            severity="medium",
            description="New user created",
            technique_id="T1136",
            technique_name="Create Account",
            tactic="Persistence",
            source_type="auth",
            source_ip="10.0.0.7",
            username=None,
            event_timestamp=now,
            created_at=now,
            raw_event_json={"test": 7},
        ),
        AlertRecord(
            rule_id="ssh_brute_force",
            rule_name="ssh_brute_force",
            severity="high",
            description="SSH brute force",
            technique_id="T1110",
            technique_name="Brute force",
            tactic="Credential Access",
            source_type="auth",
            source_ip="10.0.0.1",
            username="ubuntu",
            event_timestamp=now - timedelta(days=12),
            created_at=now - timedelta(days=12),
            raw_event_json={"test": 8},
        ),
        AlertRecord(
            rule_id="sql_injection",
            rule_name="sql_injection",
            severity="high",
            description="SQl injection",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            source_type="access",
            source_ip="10.0.0.3",
            username=None,
            event_timestamp=now - timedelta(days=14),
            created_at=now - timedelta(days=14),
            raw_event_json={"test": 9},
        ),
        AlertRecord(
            rule_id="xss_attempt",
            rule_name="xss_attempt",
            severity="medium",
            description="XSS attempt",
            technique_id="T1189",
            technique_name="Drive-by Compromise",
            tactic="Initial Access",
            source_type="access",
            source_ip="10.0.0.8",
            username=None,
            event_timestamp=now - timedelta(days=3),
            created_at=now - timedelta(days=3),
            raw_event_json={"test": 10},
        ),
        AlertRecord(
            rule_id="directory_scanning",
            rule_name="directory_scanning",
            severity="low",
            description="Directory scanning",
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            tactic="Discovery",
            source_type="access",
            source_ip="10.0.0.9",
            username=None,
            event_timestamp=now - timedelta(days=5),
            created_at=now - timedelta(days=5),
            raw_event_json={"test": 11},
        ),
        AlertRecord(
            rule_id="ssh_brute_force",
            rule_name="ssh_brute_force",
            severity="high",
            description="SSH brute force",
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            source_type="auth",
            source_ip="10.0.0.2",
            username="admin",
            event_timestamp=now - timedelta(days=7),
            created_at=now - timedelta(days=7),
            raw_event_json={"test": 12},
        ),
    ]

    session.add_all(alerts)
    session.commit()

    return alerts

def test_filter_by_rule_id(session, seeded_alerts):
    """Filtering by rule_id returns only matching alerts."""

    results = get_alerts_filtered(
        session,
        rule_id="ssh_brute_force",
    )

    assert len(results) == 4
    assert all(alert.rule_id == "ssh_brute_force" for alert in results)

def test_filter_by_technique_id(session, seeded_alerts):
    """Filtering by technique_id returns only matching alerts."""

    results = get_alerts_filtered(
        session,
        technique_id="T1190",
    )

    assert len(results) == 3
    assert all(alert.technique_id == "T1190" for alert in results)

def test_filter_by_date_range(session, seeded_alerts):
    """Start and end dates restrict results to the requested range."""

    start_date = datetime(
        2026,
        8,
        24,
    )

    end_date = datetime(
        2026,
        8,
        30,
        23,
        59,
        59,
    )

    results = get_alerts_filtered(
        session,
        start_date=start_date,
        end_date=end_date,
    )

    assert len(results) == 7

    for alert in results:
        assert start_date <= alert.event_timestamp <= end_date

def test_combined_rule_and_source_ip_filter(session, seeded_alerts):
    """Multiple filter are combined using AND."""

    results = get_alerts_filtered(
        session,
        rule_id="ssh_brute_force",
        source_ip="10.0.0.2",
    )

    assert len(results) == 2

    assert all(
        alert.rule_id == "ssh_brute_force"
        and alert.source_ip == "10.0.0.2"
        for alert in results
    )

def test_pagination_returns_correct_page_size(session, seeded_alerts):
    """Pagination returns the requested page size."""

    first_page = get_alerts_filtered(
        session,
        limit=5,
        offset=0,
    )

    second_page = get_alerts_filtered(
        session,
        limit=5,
        offset=5,
    )

    assert len(first_page) == 5
    assert len(second_page) == 5

def test_pagination_returns_correct_total_pages(session, seeded_alerts):
    """Pagination covers all seeded alerts without duplication."""

    first_page = get_alerts_filtered(
        session,
        limit=5,
        offset=0,
    )

    second_page = get_alerts_filtered(
        session,
        limit=5,
        offset=5,
    )

    third_page = get_alerts_filtered(
        session,
        limit=5,
        offset=10,
    )

    assert len(first_page) == 5
    assert len(second_page) == 5
    assert len(third_page) == 2

    all_ids = (
        [alert.id for alert in first_page]
        + [alert.id for alert in second_page]
        + [alert.id for alert in third_page]
    )

    assert len(all_ids) == 12
    assert len(set(all_ids)) == 12

def test_filter_by_tactic(session, seeded_alerts):
    """Filtering by tactic returns only matching alerts."""

    results = get_alerts_filtered(
        session,
        tactic="Credential Access",
    )

    assert len(results) == 4
    assert all(alert.tactic == "Credential Access" for alert in results)