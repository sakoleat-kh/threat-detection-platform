"""Tests for MITRE ATT&CK alert enrichment."""

from datetime import datetime, timezone

from app.mitre.mapping import enrich_alert_with_mitre
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent
from app.detection.engine import DetectionEngine
from app.detection.rules.sql_injection import SQLInjectionRule
from app.mitre.mapping import RULE_MITRE_MAPPING

def make_alert(rule_name: str) -> Alert:
    """Create an alert for testing."""
    event = NormalizedEvent(
        event_id="test-1",
        timestamp=datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
        source_type="access",
        source_ip="10.0.0.5",
        username=None,
        raw_event_type="access",
        raw_data={},
    )

    return Alert(
        rule_name=rule_name,
        severity="high",
        message="test alert",
        event=event,
    )

def test_ssh_brute_force_gets_mitre_mapping():
    """SSH brute force should recieve T1110."""
    alert = make_alert("ssh_brute_force")

    enriched = enrich_alert_with_mitre(alert)

    assert enriched.mitre_technique_id == "T1110"
    assert enriched.mitre_technique_name == "Brute Force"
    assert enriched.mitre_tactic == "Credential Access"

def test_sql_injection_gets_mitre_mapping():
    """SQL injection should receive T1190."""
    alert = make_alert("sql_injection")

    enriched = enrich_alert_with_mitre(alert)

    assert enriched.mitre_technique_id == "T1190"
    assert enriched.mitre_technique_name == (
        "Exploit Public-Facing Application"
    )
    assert enriched.mitre_tactic == "Initial Access"

def test_unknown_rule_remains_unmapped():
    """An unknown rule should not receive a MITRE mapping."""
    alert = make_alert("unknown_rule")

    enriched = enrich_alert_with_mitre(alert)

    assert enriched.mitre_technique_id is None
    assert enriched.mitre_technique_name is None
    assert enriched.mitre_tactic is None

def test_engine_enriches_alert_with_mitre():
    """DetectionEngine should automatically enrich generated alerts."""

    event = NormalizedEvent(
        event_id="sqli-1",
        timestamp=datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
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

    engine = DetectionEngine()
    engine.register_rule(SQLInjectionRule())

    alerts = engine.run([event])

    assert len(alerts) == 1
    assert alerts[0].mitre_technique_id == "T1190"
    assert alerts[0].mitre_technique_name == (
        "Exploit Public-Facing Application"
    )
    assert alerts[0].mitre_tactic == "Initial Access"

def test_all_rule_mapping():
    """Every Phase 2 rule should have the expected MITRE mapping."""

    expected_mappings = {
        "ssh_brute_force":(
            "T1110",
            "Brute Force",
            "Credential Access",
        ),
        "successful_after_failures": (
            "T1110",
            "Brute Force",
            "Credential Access",
        ),
        "excessive_sudo": (
            "T1548.003",
            "Sudo and Sudo Caching",
            "Privilege Escalation",
        ),
        "new_user_creation": (
            "T1136.001",
            "Local Account",
            "Persistence",
        ),
        "directory_scanning": (
            "T1595.003",
            "Wordlist Scanning",
            "Reconnaissance",
        ),
        "sql_injection": (
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
        ),
        "xss_attempt": (
            "T1189",
            "Drive-by Compromise",
            "Initial Access",
        ),
        "suspicious_user_agent": (
            "T1595.002",
            "Vulnerability Scanning",
            "Reconnaissance",
        )
    }

    for rule_name, expected in expected_mappings.items():
        mapping = RULE_MITRE_MAPPING[rule_name]

        assert mapping["technique_id"] == expected[0]
        assert mapping["technique_name"] == expected[1]
        assert mapping["tactic"] == expected[2]

def test_engine_alerts_have_mitre_information():
    """Every alert producted by the engine should have MITRE information."""

    event = NormalizedEvent(
        event_id="sqli-2",
        timestamp=datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
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

    engine = DetectionEngine()
    engine.register_rule(SQLInjectionRule())

    alerts = engine.run([event])

    assert alerts

    for alert in alerts:
        assert alert.mitre_technique_id is not None
        assert alert.mitre_technique_name is not None
        assert alert.mitre_tactic is not None