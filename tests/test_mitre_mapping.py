"""Tests for MITRE ATT&CK alert enrichment."""

from datetime import datetime, timezone

from app.mitre.mapping import enrich_alert_with_mitre
from app.models.alert import Alert
from app.models.normalized_event import NormalizedEvent
from app.detection.engine import DetectionEngine
from app.detection.rules.sql_injection import SQLInjectionRule

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
    """SSH brute force should recive T1110."""
    alert = make_alert("ssh_brute_force")

    enriched = enrich_alert_with_mitre(alert)

    assert enriched.mitre_technique_id == "T1110"
    assert enriched.mitre_technique_name == "Brute Force"
    assert enriched.mitre_tactic == "Credential Access"

def test_sql_injection_gets_mitre_mapping():
    """SQL injection should recive T1190."""
    alert = make_alert("sql_injection")

    enriched = enrich_alert_with_mitre(alert)

    assert enriched.mitre_technique_id == "T1190"
    assert enriched.mitre_technique_name == (
        "Exploit Public-Facing Application"
    )
    assert enriched.mitre_tactic == "Initial Access"

def test_unknown_rule_remains_unmapped():
    """An unknown rule should not recive a MITRE mapping."""
    alert = make_alert("unknown_rule")

    enriched = enrich_alert_with_mitre(alert)

    assert enriched.mitre_technique_id is None
    assert enriched.mitre_technique_name is None
    assert enriched.mitre_tactic is None

def test_engine_enriches_alert_with_mitre():
    """DetectionEngines should automatically enrich generated alerts."""

    event = NormalizedEvent(
        event_id="sqli-1",
        timestamp=datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
        source_type="access",
        source_ip="10.0.0.5",
        username=None,
        raw_event_type="access",
        raw_data={
            "path": "/search",
            "query_string": "q' OR 1=1 --",
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