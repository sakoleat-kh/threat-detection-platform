# MITRE ATT&CK Notes

## Tactic vs Technique

### Tactic
A tactic describes why an attacker performs an action - the attack's broader objective.

### Technique
A technique describes how an attacker achieves that objective.

### Sub-technique
A sub-technique provides a more specific form of a technique.

### Procedure
A procedure is a concrete example of how an adversary implements a technique.

---

## T1110 -- Brute Force
### Tactic
Credential Access

### Summary
Brute Force is when an attacker repeatedly tries different credentials or authentication values to gain access to an account or system.
### Relevant to our project

This relates directly to our SSH brute-force rule because the rule detects repeated failed SSH password attempts from the same source IP within a short period.

---

## T1078 -- Valid Accounts
### Tactic
Initial Access, Persistence, Privilege Escalation, Defense Evasion

### Summary
Valid Accounts describes an attacker using legitimate account credentials to access systems or services. Because the credentials are valid, the activity can look like normal user behavior.

### Relevant to our project
This is relevant because successful SSH authentication by itself does not prove that an attacker is present. A detection system may need additional context to determine whether a legitimate account is being misused.
---

## T1136 -- Create Account
### Tactic
Persistence

### Summary
Create account describes an attacker creating a new account that can provide another way to access a compromised system.

### Relevant to our project
This relates to our new-user creation rule because the rule detects USER_ADDED events. On Linux, this can correspond to creating a local account, which MITRE identifies as T1136.001.

---

## T1595 -- Active Scanning

### Tactic
Reconnaissance

### Summary
Active scanning involves directly probing a target's infrastructure to learn about available systems, services, or content.

### Relevant to our project
This relates to our directory-scanning rule because repeated requests for many different paths, especially paths that return 404 responses, can indicate that someone is actively enumerating web content. This behavior is particularly related to T1595.003 -- Wordlist Scanning.
---

## T1190 -- Exploit Public-Facing Application

### Tactic
Initial Access

### Summary
This technique describes exploiting a weakness in an application or service that is accessible from the Internet in order to gain unauthorized access.

### Relevant to our project
This is relevant to our SQL injection and XSS detection because attackers can send crafted web requests to public-facing applications. However, detecting an SQL injection or XSS payload does not prove that exploitation was successful.
---

## Key Takeaways

- A tactic describes why an attacker performs an action, while a technique describes how the attacker achieves the objective.
- A sub-technique gives a more specific form of a technique, while a procedure describes a concrete implementation.
- Detection rules can be mapped to MITRE ATT&CK techniques when their detected behavior matches the technique.
- A detection alert does not necessarily prove that an attack was successful; it may only identify suspicious or attempted behavior.
- ATT&CK mappings provide a common language for describing and investigating attacker behavior.
