# Threat Detection Platform

A rule-based Threat Detection Platform that analyzes security logs, detects suspicious activities using detection rules, and maps findings to the MITRE ATT&CK framework. The project is designed to demonstrate detection engineering concepts including log parsing, rule matching, ATT&CK enrichment, and security alert generation.

## Phase 1 Complete

Phase 1 establishes the foundational log ingestion and parsing layer.

### Implemented

- Linux `auth.log` parser
- Apache/Nginx Combined Log format parser
- Syslog timestamp year resolution
- Apache timestamp parsing with timezone support
- Structured authentication and access-log events
- Query-string extraction from HTTP requests
- Referer and User-Agent extraction
- Streaming log readers using generators
- CLI tools for both log types
- Malformed-input handling and targeted logging
- Parser unit tests
- Apache parser hardening tests
- End-to-end Phase 1 intergration tests

### Phase 1 Architecture

```text
                Threat Detection Platform
                            |
                            |
                      Log Input Files
                      |             |
                      |             |
                      |             |
                Linux auth.log    Apache access.log
                      |             |
                      |             |
                      |             |
                linux_parser.py    apache_parser.py
                      |             |
                      |             |
                      |             |
            auth_log_reader.py     access_log_reader.py
                      |             |
                      |             |
                      |             |
            cli_auth_reader.py     cli_access_reader.py
                      |             |
                      |             |
                      |-------------|
                             |
                             |
                    Structured Log Events
                             |
                             |
                    Detection Engineering Layer
                             |
                             |
                    MITRE ATT&CK Enrichment