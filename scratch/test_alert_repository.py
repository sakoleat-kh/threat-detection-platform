"""Manual test for the alert repository."""

from datetime import datetime, timezone

from app.models.alert import Alert
from app.models.database import Base, SessionLocal, engine
from app.models.normalized_event import NormalizedEvent
from app.repository.alert_repository import get_alert_by_id, get_all_alerts, save_alert

def main() -> None:
    """Test saving and retrieving alerts."""

    Base.metadata.create_all(bind=engine)

    event = NormalizedEvent(
        event_id="repo-test-1",
        timestamp=datetime.now(timezone.utc),
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

    alert = Alert(
        rule_name="sql_injection",
        severity="high",
        message="Possible SQL injection",
        event=event,
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public-Facing Application",
        mitre_tactic="Initial Access",
    )

    with SessionLocal() as session:
        saved = save_alert(session, alert)

        print("Saved:")
        print(saved.id, saved.rule_id, saved.severity)

        found = get_alert_by_id(session, saved.id)

        print("\nRetrieved by ID:")
        print(found.id, found.rule_name, found.technique_id)

        alerts = get_all_alerts(session)

        print("\nAll alerts:")
        for record in alerts:
            print(record.id, record.rule_name, record.severity)

if __name__ == "__main__":
    main()