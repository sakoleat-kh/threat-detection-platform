"""Manual test for AlertRecord filtering and pagination."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.database import Base
from app.models.db_alert import AlertRecord
from app.repository.alert_repository import get_alerts_filtered

def main() -> None:
    """Test each repository filter against an isolated SQLite database."""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)

    sessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    now = datetime.now(timezone.utc)

    records = [
        AlertRecord(
            rule_id="ssh_brute_force",
            rule_name="ssh_brute_force",
            severity="high",
            description="SSH brute force detected",
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            source_type="auth",
            source_ip="10.0.0.1",
            username="admin",
            event_timestamp=now - timedelta(days=3),
            created_at=now - timedelta(days=3),
            raw_event_json={"test": 1},
        ),
        AlertRecord(
            rule_id="sql_injection",
            rule_name="sql_injection",
            severity="high",
            description="Possible SQL injection",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            source_type="access",
            source_ip="10.0.0.2",
            username=None,
            event_timestamp=now - timedelta(days=2),
            created_at=now - timedelta(days=2),
            raw_event_json={"test": 2}
        ),
        AlertRecord(
            rule_id="ssh_brute_force",
            rule_name="ssh_brute_force",
            severity="medium",
            description="Another SSh brute force",
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            source_type="auth",
            source_ip="10.0.0.3",
            username="root",
            event_timestamp=now - timedelta(days=1),
            created_at=now - timedelta(days=1),
            raw_event_json={"test": 3},
        ),
    ]

    with sessionLocal() as session:
        session.add_all(records)
        session.commit()

        print("1. Rule filter:")
        results = get_alerts_filtered(
            session,
            rule_id="ssh_brute_force",
        )
        print([alert.rule_id for alert in results])

        print("\n2. Technique filter:")
        results = get_alerts_filtered(
            session,
            technique_id="T1190",
        )
        print([alert.technique_id for alert in results])

        print("\n3 Source IP filter:")
        results = get_alerts_filtered(
            session,
            source_ip="10.0.0.2",
        )
        print([alert.source_ip for alert in results])

        print("\n4. Start date filter:")
        results = get_alerts_filtered(
            session,
            start_date=now - timedelta(days=2),
        )
        print([alert.id for alert in results])

        print("\n5. End date filter:")
        results = get_alerts_filtered(
            session,
            end_date=now - timedelta(days=2),
        )

        print([alert.id for alert in results])

        print("\n6. Combined rule + source IP:")
        results = get_alerts_filtered(
            session,
            rule_id="ssh_brute_force",
            source_ip="10.0.0.3",
        )
        print([(alert.rule_id, alert.source_ip) for alert in results])

        print("\n7. Pagination:")
        results = get_alerts_filtered(
            session,
            limit=1,
            offset=1,
        )
        print([(alert.id, alert.rule_id) for alert in results])

if __name__ == "__main__":
    main()

