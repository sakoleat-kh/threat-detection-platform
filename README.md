# Threat Detection Platform

A rule-based Threat Detection Platform that analyzes security logs, detects suspicious activities using detection rules, and maps findings to the MITRE ATT&CK framework. The project is designed to demonstrate detection engineering concepts including log parsing, rule matching, ATT&CK enrichment, and security alert generation.

## Linux auth.log Parser

The parser:
- Parser Linux syslog-style auth.log entries
- Resolves year for traditional syslog timestamps
- Supports ISO timestamps
- Uses a pattern registry for event handlers
- Handles malformed input without crashing
- Streams auth.log files using a generator
- Provides a CLI for displaying events and event counts