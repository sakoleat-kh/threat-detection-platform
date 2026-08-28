"""Repository functions for persistent detection alerts."""

from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.db_alert import AlertRecord


def save_alert(session: Session, alert: Alert) -> AlertRecord:
    """save an Alert as an AlertRecord and return the stored record."""

    record = AlertRecord(
        rule_id=alert.rule_name,
        rule_name=alert.rule_name,
        severity=alert.severity,
        description=alert.message,
        technique_id=alert.mitre_technique_id,
        technique_name=alert.mitre_technique_name,
        tactic=alert.mitre_tactic,
        source_type=alert.event.source_type,
        source_ip=alert.event.source_ip,
        username=alert.event.username,
        event_timestamp=alert.event.timestamp,
        created_at=datetime.now(timezone.utc),
        raw_event_json=alert.event.raw_data,
    )

    session.add(record)
    session.commit()
    session.refresh(record)

    return record

def get_alert_by_id(
    session: Session,
    alert_id: int,
) -> Optional[AlertRecord]:
    """Return an alert by database ID, or None if it does not exist."""

    statement = select(AlertRecord).where(AlertRecord.id == alert_id)

    return session.scalars(statement).first()

def get_all_alerts(
    session: Session,
    limit: int = 20,
    offset: int = 0,
) -> List[AlertRecord]:
    """Return alerts using limit and offset pagination."""

    statement = (
        select(AlertRecord)
        .order_by(AlertRecord.id)
        .limit(limit)
        .offset(offset)
    )

    return list(session.scalars(statement).all())