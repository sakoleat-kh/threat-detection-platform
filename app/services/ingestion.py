"""End-to-eng log ingestion and alert persistence service."""

from datetime import datetime
from pathlib import Path

from app.detection.engine import DetectionEngine
from app.models.database import SessionLocal
from app.parsers.access_log_reader import read_access_log
from app.parsers.auth_log_reader import read_auth_log
from app.repository.alert_repository import save_alert
from app.services.normalizer import normalize_access_event, normalize_auth_event

def ingest_logs(
    auth_log_path: str | Path,
    access_log_path: str | Path,
    engine: DetectionEngine,
    reference_date: datetime,
) -> int:
    """Parse, normalize, detect, enrich, and persist alerts."""

    normalize_events = []

    for event in read_auth_log(auth_log_path, reference_date):
        normalize_events.append(normalize_auth_event(event))

    for event in read_access_log(access_log_path):
        normalize_events.append(normalize_access_event(event))

    alerts = engine.run(normalize_events)

    with SessionLocal() as session:
        for alert in alerts:
            save_alert(session, alert)

    return len(alerts)