"""Run the end-to-end log ingestion pipeline."""

from datetime import datetime

from app.services.detection_engine import build_engine
from app.services.ingestion import ingest_logs


def main() -> None:
    """Run ingestion against the sample log files."""

    engine = build_engine()

    alert_count = ingest_logs(
        auth_log_path="data/sample_logs/auth_sample.log",
        access_log_path="data/sample_logs/access_sample.log",
        engine=engine,
        reference_date=datetime.now(),  # noqa: DTZ005
    )

    print(f"Alerts persisted: {alert_count}")


if __name__ == "__main__":
    main()