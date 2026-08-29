"""End-to-eng log ingestion and alert persistence service."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.detection.engine import DetectionEngine
from app.models.database import SessionLocal
from app.parsers.access_log_reader import read_access_log
from app.parsers.auth_log_reader import read_auth_log
from app.repository.alert_repository import save_alert
from app.services.normalizer import normalize_access_event, normalize_auth_event


@dataclass
class IngestionResult:
    """Summary of one ingestion run."""

    auth_lines_processed: int
    access_lines_processed: int
    alerts_generated: int
    alerts_by_rule: dict[str, int]
    alerts_saved: int

def ingest_logs(
    auth_log_path: str | Path,
    access_log_path: str | Path,
    engine: DetectionEngine,
    reference_date: datetime,
) -> int:
    """Parse, normalize, detect, enrich, and persist alerts."""

    normalize_events = []
    auth_lines_processed= 0
    access_lines_processed = 0

    if auth_log_path is not None:
        with open(auth_log_path, "r", encoding="utf-8") as file:
            auth_lines = [line for line in file if line.strip()]

        auth_lines_processed = len(auth_lines)

        for line in auth_lines:
            from app.parsers.linux_parser import parse_line

            event = parse_line(line.strip(), reference_date)

            if event is not None:
                normalize_events.append(
                    normalize_auth_event(event)
                )

    if access_log_path is not None:
        with open(access_log_path, "r", encoding="utf-8") as file:
            access_lines = [line for line in file if line.strip()]

        access_lines_processed = len(access_lines)

        for line in access_lines:
            from app.parsers.apache_parser import parse_access_line

            event = parse_access_line(line.strip())

            if event is not None:
                normalize_events.append(
                    normalize_access_event(event)
                )
    alerts = engine.run(normalize_events)

    alerts_by_rule = Counter(alert.rule_name for alert in alerts)

    alerts_saved = 0

    with SessionLocal() as session:
        for alert in alerts:
            save_alert(session, alert)
            alerts_saved += 1

    return IngestionResult(
        auth_lines_processed=auth_lines_processed,
        access_lines_processed=access_lines_processed,
        alerts_generated=len(alerts),
        alerts_by_rule=dict(alerts_by_rule),
        alerts_saved=alerts_saved,
    )