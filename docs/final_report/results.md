# Evaluation and Results

## 4.1 Evaluation Approach

The Threat Detection Platform was evaluated through automated testing, detection-rule validation, API testing, dashboard testing, and Docker end-to-end testing.

The evaluation focused on verifying that the implemented components work together correctly, that detection rules generate the expected alerts, that alerts are persisted in the database, and that the REST API and dashboard expose the resulting information correctly.

No unsupported claims about enterprise-scale performance, detection accuracy, or production throughput are made because these metrics were not formally benchmarked.

## 4.2 Automated Testing

The project includes an automated test suite covering parsers, normalization, detection rules, repositories, API endpoints, and other core components.

The final regression test produced:

- **189 tests passed**
- **1 warning**

The warning was a Starlette deprecation warning related to the installed HTTP client configuration. It did not cause any test failures and was not related to application functionality.

The successful test suite indicates that the implemented components and their integration points are functioning as expected under the tested scenarios.

## 4.3 Test Coverage

The final test run achieved **95% code coverage**.

The coverage report contained:

- **741 statements**
- **39 missed statements**
- **95% overall coverage**

The remaining uncovered code was intentional and primarily consisted of:

- The abstract detection method in `rule_base.py`.
- CLI wrapper code in the parser reader scripts.

These areas were not considered necessary to exercise through the main automated test suite because they either define abstract behavior or provide thin command-line entry points around already tested functionality.

## 4.4 Detection Validation

The detection pipeline was also validated using representative authentication and Apache access log samples.

### Authentication Log Validation

The authentication sample contained **200 log lines**.

The ingestion process produced:

- **200 lines processed**
- **1 alert generated**

This verified the complete path from authentication log ingestion through parsing, normalization, detection, alert creation, and persistence.

### Apache Access Log Validation

The Apache access sample contained **200 log lines**.

The ingestion process produced:

- **200 lines processed**
- **0 alerts generated**

The result was expected for the supplied access-log sample and verified that normal access activity did not incorrectly produce alerts in that test scenario.

### MITRE Detection Pipeline Validation

The MITRE pipeline dry run processed:

- **400 normalized events**
- **1 alert generated**

The generated alert was associated with:

- **Technique:** T1548.003 — Sudo and Sudo Caching
- **Tactic:** Privilege Escalation

This confirmed that normalized events could pass through the detection engine and produce an alert enriched with MITRE ATT&CK information.

## 4.5 API and Dashboard Validation

The REST API was tested as part of the Docker end-to-end validation.

The following functionality was verified:

- Health-check endpoint.
- Alert listing.
- Individual alert retrieval.
- Alert filtering.
- Combined alert filters.
- Date-based filtering.
- Empty filter results.
- Alert statistics.
- Alert detail information.

The dashboard was also manually validated. The following functionality was confirmed:

- Alert table display.
- Filtering controls.
- Date-range filtering.
- Refresh behavior.
- Alert detail modal.
- Alert statistics.
- Rule, technique, and tactic charts.
- Empty-state behavior.

During the validation process, a mismatch was found between the statistics cards and the live alert data. The dashboard was subsequently updated to load the statistics from the `/stats/` API endpoint. The statistics cards, charts, and alert table were then verified to display consistent results.

## 4.6 Docker and Persistence Validation

The application was tested using Docker Compose with a named persistent volume for the SQLite database.

The end-to-end validation confirmed that:

1. The Docker image built successfully.
2. The application container started successfully.
3. The health-check endpoint returned a successful response.
4. Authentication logs could be ingested through the API.
5. Apache access logs could be ingested through the API.
6. Generated alerts were available through the `/alerts/` endpoint.
7. Alert statistics were available through the `/stats/` endpoint.
8. The application could be stopped and restarted without losing previously stored alerts.

After restarting the Docker Compose application, the previously generated alerts remained available. This verified that the configured named Docker volume successfully persisted the SQLite database across container restarts.

## 4.7 Results Summary

| Evaluation Area | Result |
|---|---|
| Automated tests | 189 passed |
| Test coverage | 95% |
| Authentication sample | 200 lines processed, 1 alert |
| Access sample | 200 lines processed, 0 alerts |
| MITRE pipeline dry run | 400 normalized events, 1 alert |
| API validation | Passed |
| Dashboard validation | Passed |
| Docker build and startup | Passed |
| Database persistence after restart | Passed |

Overall, the evaluation demonstrates that the platform's implemented detection pipeline, alert persistence, MITRE enrichment, REST API, dashboard, and Docker deployment operate correctly under the tested scenarios.

## 4.8 Limitations

The evaluation should be interpreted within the scope of the implemented system and test environment.

### Log Source Scope

The platform currently focuses on supported authentication and Apache access log formats. It does not represent a complete multi-source enterprise log collection system.

### Rule-Based Detection

Detection is based on predefined thresholds, conditions, and signatures. The platform does not currently provide machine-learning-based anomaly detection or adaptive behavioral baselines.

### Signature and Threshold Limitations

Pattern-based and threshold-based detection can produce false positives or false negatives depending on the input data and attack variations. The configured thresholds and signatures would require further tuning against larger and more diverse datasets.

### Performance Evaluation

The project does not include a formal benchmark of production-scale throughput, latency, memory usage, or concurrent ingestion capacity. Therefore, no enterprise-scale performance claims are made.

### Production Security Monitoring

The platform demonstrates the core detection and alerting workflow but does not provide the full capabilities of a production SIEM or SOC platform, such as large-scale distributed collection, advanced correlation across many data sources, automated incident response, or comprehensive alert lifecycle management.

## 4.9 Conclusion

The evaluation confirms that the implemented platform successfully performs the core functions defined within the project scope. The automated test suite, detection validation, API testing, dashboard validation, and Docker end-to-end testing provide evidence that the main components operate together as an integrated threat detection system.

The results also identify clear areas for future development, particularly broader log-source support, more advanced detection techniques, larger-scale evaluation datasets, performance benchmarking, and additional production-oriented security monitoring capabilities.