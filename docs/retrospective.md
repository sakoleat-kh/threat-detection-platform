# Project Retrospective

## What Went Better Than Expected

The project developed into a complete end-to-end threat detection platform rather than only a detection engine. The eight detection rules were integrated with MITRE ATT&CK mappings and exposed through the FastAPI API and web dashboard.

The automated test suite also reached 189 passing tests with 95% coverage. Docker deployment and database persistence were successfully validated from a completely fresh clone, which increased confidence that the project can be reproduced outside the development environment.

## What Took Longer Than Expected

Integrating the different layers took longer than expected. The project required the parsing, normalization, detection, MITRE mapping, database persistence, API, and dashboard components to work together correctly.

Integration testing also revealed issues that were not obvious when individual components were tested separately. In particular, Docker end-to-end testing and dashboard validation required additional debugging and refinement.

Preparing the documentation, screenshots, presentation, and final demonstration also required significant additional validation near the end of the project.

## What I Would Architect Differently

If I rebuilt the project from the beginning, I would separate the demonstration and test environments from the development environment from the start. This would reduce the risk of development data affecting demonstrations and final validation.

I would also design the dashboard statistics to be fully data-driven from the beginning rather than introducing hard-coded values during early development. Finally, I would plan the documentation and presentation artifacts earlier so that final-stage preparation required less rework.

## Three Biggest Technical Lessons

1. **End-to-end integration matters as much as individual components.** A parser, detection rule, API, or dashboard can work independently while the complete system still has integration problems.

2. **Automated testing and fresh-environment testing catch different problems.** The 189-test suite provided confidence in application behavior, while fresh-clone Docker testing validated deployment, initialization, ingestion, detection, and database persistence.

3. **Explainability is valuable in security detection.** Clear rule conditions, thresholds, severity levels, and MITRE ATT&CK mappings make security alerts easier to understand, validate, and investigate.
