"""Run the end-to-end log ingestion pipeline."""

from datetime import datetime

from app.detection.engine import DetectionEngine
from app.detection.rules.directory_scanning import DirectoryScanningRule
from app.detection.rules.excessive_sudo import ExcessiveSudoRule
from app.detection.rules.new_user_creation import NewUserCreationRule
from app.detection.rules.sql_injection import SQLInjectionRule
from app.detection.rules.ssh_brute_force import SSHBruteForceRule
from app.detection.rules.successful_after_failures import SuccessfulAfterFailuresRule
from app.detection.rules.suspicious_user_agent import SuspiciousUserAgentRule
from app.detection.rules.xss_attempt import XSSAttemptRule
from app.services.ingestion import ingest_logs

def build_engine() -> DetectionEngine:
    """Create a detection engine with all eight Phase 2 rules."""

    engine = DetectionEngine()

    engine.register_rule(SSHBruteForceRule())
    engine.register_rule(SuccessfulAfterFailuresRule())
    engine.register_rule(ExcessiveSudoRule())
    engine.register_rule(NewUserCreationRule())
    engine.register_rule(DirectoryScanningRule())
    engine.register_rule(SQLInjectionRule())
    engine.register_rule(XSSAttemptRule())
    engine.register_rule(SuspiciousUserAgentRule())

    return engine

def main() -> None:
    """Run ingestion against the sample log files."""

    engine = build_engine()

    alert_count = ingest_logs(
        auth_log_path="data/sample_logs/auth_sample.log",
        access_log_path="data/sample_logs/access_sample.log",
        engine=engine,
        reference_date=datetime.now(),
    )

    print(f"Alerts persisted: {alert_count}")

if __name__ == "__main__":
    main()