"""MITRE ATT&CK mappings for detetion rules."""

from app.models.alert import Alert

RULE_MITRE_MAPPING = {
    "ssh_brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "successful_after_failures": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "excessive_sudo": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
    },
    "new_user_creation": {
        "technique_id": "T1136.001",
        "technique_name": "Local Account",
        "tactic": "persistence",
    },
    "directory_scanning": {
        "technique_id": "T1595.003",
        "technique_name": "Wordlist Scanning",
        "tactic": "Reconnaissance",
    },
    "sql_injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    "xss_attempt": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic": "Initail Access",
    },
    "suspicious_user_agent": {
        "technique_id": "T1595.002",
        "technique_name": "Vulnerability Scanning",
        "tactic": "Reconnaissance",
    },
}

def enrich_alert_with_mitre(alert: Alert) -> Alert:
    """Add MITRE ATT&CK information to an alert."""

    mapping = RULE_MITRE_MAPPING.get(alert.rule_name)

    if mapping is None:
        return alert

    alert.mitre_technique_id = mapping["technique_id"]
    alert.mitre_technique_name = mapping["technique_name"]
    alert.mitre_tactic = mapping["tactic"]

    return alert