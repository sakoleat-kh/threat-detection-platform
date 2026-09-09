# Detection Rules

## 3.1 Overview

The Threat Detection Platform uses eight detection rules to identify suspicious authentication activity, privilege escalation behavior, web attacks, account creation, directory scanning, and suspicious web clients. The rules operate on normalized authentication and access events.

Each rule applies a specific detection method. Some rules use thresholds and time windows, while others use event conditions or pattern matching. When a rule detects suspicious behavior, it produces an alert containing the rule name, severity, event information, and MITRE ATT&CK mapping.

## 3.2 Detection Rule Summary

| Rule | Log Type | Detection Method | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| Excessive Sudo | Authentication | Threshold + time window | High | T1548.003 — Sudo and Sudo Caching |
| SSH Brute Force | Authentication | Failed-login threshold + time window | High | T1110 — Brute Force |
| Successful After Failures | Authentication | Failed-login threshold before success | High | T1110 — Brute Force |
| New User Creation | Authentication | Event-based detection | High | T1136.001 — Local Account |
| Directory Scanning | Access | Path-count + 404 ratio + time window | High | T1595.003 — Wordlist Scanning |
| SQL Injection | Access | Pattern matching | High | T1190 — Exploit Public-Facing Application |
| XSS Attempt | Access | Pattern matching | High | T1189 — Drive-by Compromise |
| Suspicious User Agent | Access | Indicator matching | Low | T1595.002 — Vulnerability Scanning |

## 3.3 Excessive Sudo

### Purpose

The Excessive Sudo rule identifies unusually frequent sudo activity that may indicate privilege escalation attempts or suspicious administrative behavior.

### Detection Logic

The rule processes authentication events and monitors two types of sudo activity:

- `sudo_command`
- `sudo_auth_failed`

A sliding five-minute window is used to evaluate activity.

An alert is generated when either of the following conditions is reached:

- At least **10 sudo commands** occur within five minutes.
- At least **3 sudo authentication failures** occur within five minutes.

The resulting alert is classified as **High** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1548.003 — Sudo and Sudo Caching
- **Tactic:** Privilege Escalation

## 3.4 SSH Brute Force

### Purpose

The SSH Brute Force rule identifies repeated failed SSH password authentication attempts from the same source.

### Detection Logic

The rule groups failed SSH password authentication events by source IP and maintains a five-minute sliding window.

An alert is generated when at least **5 failed SSH password attempts** are observed from the same source IP within five minutes.

The alert is classified as **High** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1110 — Brute Force
- **Tactic:** Credential Access

## 3.5 Successful Authentication After Failures

### Purpose

This rule detects a successful SSH authentication that occurs after repeated failed authentication attempts. This behavior can indicate that an attacker eventually obtained or guessed valid credentials.

### Detection Logic

The rule tracks failed SSH password authentication attempts from each source IP.

When a successful SSH password authentication occurs, the rule checks the recent failure window. If at least **3 failed attempts** occurred within the configured **five-minute window**, an alert is generated.

The alert is classified as **High** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1110 — Brute Force
- **Tactic:** Credential Access

## 3.6 New User Creation

### Purpose

The New User Creation rule detects the creation of a new local user account.

### Detection Logic

When a matching event is observed, the rule generates an alert. This rule is event-based rather than threshold-based because a single unexpected account-creation event can be significant.

The alert is classified as **High** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1136.001 — Local Account
- **Tactic:** Persistence

## 3.7 Directory Scanning

### Purpose

The Directory Scanning rule identifies behavior consistent with automated discovery or wordlist-based scanning of web paths.

### Detection Logic

The rule processes web access events and groups activity by source IP.

Within a five-minute window, it evaluates:

- The number of distinct requested paths.
- The proportion of requests that return HTTP 404 responses.

An alert is generated when both conditions are satisfied:

- At least **15 distinct paths** are requested.
- At least **80% of the requests return HTTP 404**.

The alert is classified as **High** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1595.003 — Wordlist Scanning
- **Tactic:** Reconnaissance

## 3.8 SQL Injection

### Purpose

The SQL Injection rule identifies web requests containing patterns associated with SQL injection attempts.

### Detection Logic

This rule is signature-based rather than threshold-based.

It examines access-event request data and compares it against predefined SQL injection patterns. When a request matches one of the configured patterns, the rule generates an alert.

Because the detection is based on the characteristics of an individual request, no event-count threshold or time window is required.

The alert is classified as **High** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1190 — Exploit Public-Facing Application
- **Tactic:** Initial Access

## 3.9 Cross-Site Scripting (XSS)

### Purpose

The XSS Attempt rule identifies recognizable cross-site scripting payloads in web requests.

### Detection Logic

The rule examines the requested path and query string and compares them against predefined XSS signatures.

The signatures include patterns associated with:

- Script tag injection.
- JavaScript URLs.
- Common inline event handlers.
- Executable HTML elements such as `img`, `svg`, `iframe`, `object`, and `embed`.
- HTML or script-tag injection techniques.

When a request matches a configured XSS pattern, an alert is generated.

The alert is classified as **High** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1189 — Drive-by Compromise
- **Tactic:** Initial Access

## 3.10 Suspicious User Agent

### Purpose

The Suspicious User Agent rule identifies web clients that may represent scanning tools or automated reconnaissance.

### Detection Logic

The rule examines the User-Agent value in access events.

It generates an alert when:

- The User-Agent is missing, or
- The User-Agent contains a known suspicious tool identifier.

The configured suspicious identifiers include:

- `sqlmap`
- `nikto`
- `curl`
- `python-requests`
- `nmap`
- `masscan`

This rule does not use a numerical threshold or time window. Each matching access event can generate an alert.

The alert is classified as **Low** severity.

### MITRE ATT&CK Mapping

- **Technique:** T1595.002 — Vulnerability Scanning
- **Tactic:** Reconnaissance

## 3.11 Rule Design Considerations

The detection rules use different detection strategies because different security behaviors require different indicators.

Threshold-based rules are useful for identifying abnormal frequency over a period of time. Event-based rules are appropriate when a single event can be significant. Signature-based rules are useful for recognizing known attack patterns in web requests.

The combination of these approaches allows the platform to detect both repeated behavioral activity and individual suspicious events while keeping each rule's logic relatively focused and independently testable.
