# 2. System Architecture

## 2.1 Architecture Overview

The Threat Detection Platform follows a layered architecture in which log ingestion, parsing, normalization, detection, alert persistence, and presentation are separated into distinct components.

The architecture is designed to transform raw security log data into structured detection alerts through a defined processing pipeline. The main application is implemented in Python using FastAPI for the REST API, SQLAlchemy for database interaction, and SQLite for persistent storage. The application can also be deployed as a Docker container with persistent database storage.

The high-level architecture is shown below.

```mermaid
flowchart TD

    A[Authentication Log File] --> B[Ingestion Layer]
    C[Apache Access Log File] --> B

    B --> D[Log Parsers]

    D --> E[Normalized Events]

    E --> F[Detection Engine]

    F --> G[Detection Rules]

    G --> H[Detection Alert]

    H --> I[MITRE ATT&CK Mapping]

    I --> J[Alert Repository]

    J --> K[SQLite Database]

    K --> L[FastAPI API]

    L --> M[Web Dashboard]

    L --> N[API Clients]

```text

The platform therefore follows the general flow:

Raw Logs → Ingestion → Parsing → Normalization → Detection → Alert Generation → MITRE ATT&CK Mapping → Persistence → API → Dashboard

## 2.2 Log Ingestion

The ingestion layer provides the entry point for log data entering the platform.

The FastAPI ingestion endpoint accepts an uploaded log file together with type. The supported inputs include authentication logs and Apache-style access logs.

The ingestion service coordinates processing of the uploaded data and passes the appropriate log entries to the corresponding parser.

This separation allows the ingestion mechanism to remain independent from the source-specific parsing logic.

## 2.3 Log Parsing

The parser layer converts raw text log entries into structured event objects.

Authentication logs are processed using the Linux authentication parser, while Apache access logs are processed using the Apache parser. Additional reader modules handle reading the corresponding log files and provide the input to the parsing functions.

The parser layer is responsible for understanding the syntax and structure of each supported log format. It does not perform threat detection itself.

This separation is important because detection rules should operate on structured events rather than depending directly on raw log syntax.

## 2.4 Event Normalization

After parsing, source-specific events are converted into a common normalized event representation.

The normalization service provides functions for converting authentication and access events into the shared normalized event structure used by the detection system.

Normalization allows the detection engine to work with a consistent event model regardless of the original log source.

For example, authentication and web access events have different source formats and fields, but they can both be represented using common concepts such as timestamps, usernames, source addresses, HTTP information, commands, and other relevant event attributes.

## 2.5 Detection Engine

The detection engine is responsible for evaluating normalized events against the detection rules implemented by the platform.

The detection architecture separates the engine from individual rules. The engine coordinates rule execution, while each rule contains the logic required to identify a particular suspicious behavior.

The platform currently includes eight detection rules:

1. Excessive Sudo Activity
2. SSH Brute force
3. Suspicious User Agent
4. SQL Injection Attempt
5. XSS Attempt
6. Directory Scanning
7. New User Creation
8. Successful Authentication After Failures

This rule-based approach makes the detection layer modular. Individual rules can be tested, maintained, or extended without requiring the entire detection engine to be redesigned.

## 2.6 Alert Generation and MITRE ATT&CK Mapping

When a detection rule identifies suspicious behavior, the platform generates a structured alert containing information such as the rule identifier, severity, description, source information, username, event timestamp, and other relevant event data.

Detection rules are associated with MITRE ATT&CK techniques and tactics. The MITRE mapping component provides the corresponding ATT&CK information for detected activity.

This allows generated alerts to provide additional security context beyond the rule name itself. For example, a detection can be associated with a specific ATT&CK technique identifier and its corresponding tactic.

This mapping is limited to the techniques represented by the detection rules implemented in this project and does not attempt to provide complete MITRE ATT&CK coverage.

## 2.7 Alert Persistence

Generated alerts are stored using the repository layer and SQLAlchemy database models.

The alert repository provides operations for saving alerts, retrieving individual alerts, retrieving multiple alerts, filtering alerts, and calculating alert statistics.

SQLite is used as the project's persistent database. In the Docker deployment, the database is stored in a persistent Docker volume so that alert data remains available when the application container is restarted.

This persistence layer separates database operations from the detection and API layers.

## 2.8 REST API

The FastAPI application provides the external interface for interacting with the platform.

The main API areas include:

- **Health:** Provides a basic health-check endpoint.
- **Ingestion:** Accepts authentication or access log files for processing.
- **Alerts:** Provides alert retrieval, filtering, pagination, and individual alert lookup.
- **Statistics:** Provides aggregated alert counts by detection rule, MITRE ATT&CK technique, and tactic.

The API therefore acts as the boundary between the backend processing system and clients such as the web dashboard.

## 2.9 Web Dashboard

The web dashboard provides a visual interface for reviewing the alerts and statistics generated by the platform.

It retrieves data from the FastAPI endpoints and presents alert information in a user-friendly format. The dashboard includes alert filtering, alert details, statistics, and charts for examining the current detection data.

The dashboard is therefore a presentation layer rather than part of the core detection pipeline. Detection decisions are made by the backend detection engine, while the dashboard presents the resulting information to the user.

## 2.10 Docker Deployment

The application can be deployed using Docker.

The Docker image contains the Python application and its dependencies and runs the FastAPI application using Uvicorn. Docker Compose is used to configure the application service, expose the API on port 8000, and mount a named volume for persistent database storage.

The deployment architecture can therefore be summarized as:

Docker Host:
 |
 |
 --------- Threat Detection Platform Container
           |
           |------ FastAPI Application
           |       |
           |       |------ Ingestion API
           |       |
           |       |------ Statistics API
           |
           |
           |------ Detection Pipeline
           |       |   
           |       |------- Parsers
           |       |------- Normalizer
           |       |------- Detection Engine
           |       |------- Detection Rules
           |
           |
           ------- SQLite Database
                   |
                   |
                   ------ Persistent Docker Volume


## 2.11 Architectural Design Principles

The system architecture follows several principles:

- **Separation of concerns:** Parsing, normalization, detection, persistence, and presentation are implemented as separate layers.
- **Modularity:** Detection rules are independent components coordinated by the detection engine.
- **Consistent event representation:** Normalization provides a common structure for different log sources.
- **API separation:** The REST API provides a clear interface between backend processing and presentation clients.
- **Deployability:** Docker provides a reproducible runtime environment and persistent storage configuration.
- **Testability:** Components are separated sufficiently to allow individual units and complete processing paths to be tested.

Overall, the architecture provides an end-to-end pipeline for transforming supported security logs into persistent, contextualized alerts that can be accessed through an API and visualized through the dashboard.


Save if:
- `Ctrl + o`
- `Enter`
- `Ctrl + X`

### Then verify both reposrt files

Run:

```bash
cat docs/final_report/architecture.md
