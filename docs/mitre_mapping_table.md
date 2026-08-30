# MITRE ATT&CK Rule Mapping

| Rule | Detection | MITRE Technique | Tactic | Justification |
|------|------|------|------|------|
| Rule 1 | SSH Brute Force | T1110 -- Brute Force | Credential Access | The rule detects repeated failed SSH authentication attempts, which directly matches brute-force password guessing behavior. |
| Rule 2 | Successful After Failures | T1110 -- Brute Force | Credential Access | The combination of repeated authentication failures followed by a successful login is consistent with the brute-force detection behavior described by MITRE. |
| Rule 3 | Excessive Sudo | T1548.003 -- Sudo and Sudo Caching | Privilege Escalation | The rule detects repeated sudo activity, which is relevant to abuse of sudo for elevated privileges. |
| Rule 4 | New User Creation | T1136.001 -- Local Account | Persistence | The rule detects Linux local account creation events, which directly corresponds to the Local Account sub-technique of Create Account. |
| Rule 5 | Directory Scanning | T1595.003 -- Wordlist Scanning | Reconnaissance | The rule detects rapid requests for many distinct web paths, resembling enumeration of web content using a path list. |
| Rule 6 | SQL Injection | T1190 -- Exploit Public-Facing Application | Initial Access | SQL injection can be used to exploit weaknesses in public-facing web applications, making T1190 the closest ATT&CK representation. |
| Rule 7 | XSS Attempt | T1189 -- Drive-by Compromise | Initial Access | XSS can be used to inject malicious scripts into web content and compromise users who visit the affected site. |
| Rule 8 | Suspicious User-Agent | T1595.002 -- Vulnerability Scanning | Reconnaissance | Known scanner User-Agents can indicate reconnaissance or vulnerability scanning, although this mapping is only partial because the rule also detects generic clients and missing User-Agents |

## Mapping Limitations

Some detections do not map perfectly to a single ATT&CK technique.

Rule 8 is the clearest example. A suspicious User-Agent is an indicator of potentially automated or scanning activity, but it does not by itself prove vulnerability scanning. The rule also treats missing User-Agents as suspicious, which has no direct one-to-one ATT&CK technique mapping.

Rule 7 detects an XSS payload attempt, but the presence of a payload does not prove successful compromise of a user's browser. Therefore, T1189 should be treated as a contextual or conditional mapping rather than proof that Drive-by Compromise occurred.

Rule 6 similarly detects an SQL injection attempt rather than proving successful exploitation.