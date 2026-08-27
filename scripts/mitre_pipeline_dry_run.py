"""Run the complete detection pipeline against sample log data."""

from collections import Counter
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
from app.parsers.auth_log_reader import read_auth_log
from app.parsers.access_log_reader import read_access_log
from app.services.normalizer import normalize_access_event, normalize_auth_event

ACCESS_LOG = "data/sample_logs/access_sample.log"
AUTH_LOG = "data/sample_logs/auth_sample.log"

def load_events():
    """Load and normalize saple access and authentication logs."""

    events = []

    for event in read_access_log(ACCESS_LOG):
        events.append(normalize_access_event(event))

    reference_date = datetime.now()

    for event in read_auth_log(AUTH_LOG, reference_date):
        events.append(normalize_auth_event(event))

    return events

def build_engine() -> DetectionEngine:
    """Create an engine containing all eight Phase 2 rules."""

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

def print_summary(alerts):
    """Print a readable MITRE ATT&CK alert summary."""

    counts = Counter(
        (
            alert.mitre_technique_id,
            alert.mitre_technique_name,
            alert.mitre_tactic,
        )
        for alert in alerts
    )

    print("\nMITRE ATT&CK ALERT SUMMARY")
    print("=" * 90)

    print(
        f"{'Technique':<12} "
        f"{'Tactic':<22} "
        f"{'Count':<8} "
        f"Example Alert"
    )

    print("=" * 90)

    for (technique_id, technique_name, tactic), count in sorted(counts.items()):
        examples = next(
            alert
            for alert in alerts
            if alert.mitre_technique_id == technique_id
        )

        print(
            f"{technique_id:<12} "
            f"{tactic:<22} "
            f"{count:<8} "
            f"{examples.message}"
        )

        print(f"        {technique_name}")
    print("=" * 90)

def main():
    """Run the complete pipeline."""

    events = load_events()

    engine = build_engine()

    alerts = engine.run(events)

    print(f"\nNormalized events: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    print_summary(alerts)

if __name__ == "__main__":
    main()