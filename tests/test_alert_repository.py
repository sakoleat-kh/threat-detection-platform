"""Tests for the alert repository."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.models.database import Base
from app.models.db_alert import AlertRecord
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent
from app.repository.alert_repository import get_alert_by_id, save_alert, get_all_alerts


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

def make_alert() -> Alert:
    """Create a sample alert for repository tests."""

    event = NormalizedEvent(
        event_id="test-1",
        timestamp=datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc),
        source_type="access",
        source_ip="10.0.0.5",
        username=None,
        raw_event_type="access",
        raw_data={
            "path": "/search",
            "query_string": "q=' OR 1=1 --",
            "status_code": 200,
        },
    )

    return Alert(
        rule_name="sql_injection",
        severity="high",
        message="Possible SQL injection",
        event=event,
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public-Facing Application",
        mitre_tactic="Initial Access",
    )

def test_save_then_retrieve_by_id(session):
    """An alert can be saved and retrieved by its database ID."""

    alert = make_alert()

    saved = save_alert(session, alert)

    retrieved = get_alert_by_id(session, saved.id)

    assert retrieved is not None
    assert retrieved.id == saved.id
    assert retrieved.rule_id == "sql_injection"
    assert retrieved.rule_name == "sql_injection"
    assert retrieved.severity == "high"
    assert retrieved.technique_id == "T1190"
    assert retrieved.technique_name == "Exploit Public-Facing Application"
    assert retrieved.tactic == "Initial Access"
    assert retrieved.source_ip == "10.0.0.5"

def test_get_all_alerts_pagination(session):
    """get_all_alerts should respect limit and offset."""

    for _ in range(5):
        save_alert(session, make_alert())

    first_page = get_all_alerts(session, limit=2, offset=0)
    second_page = get_all_alerts(session, limit=2, offset=2)

    assert len(first_page) == 2
    assert len(second_page) == 2

    assert first_page[0].id < first_page[1].id
    assert second_page[0].id < second_page[1].id

    assert first_page[1].id < second_page[0].id

def test_get_alert_by_id_returns_none_for_missing_id(session):
    """A missing alert ID should return None."""

    result = get_alert_by_id(session, 9999)

    assert result is None