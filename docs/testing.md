# Testing and Coverage

## Overview

The Threat Detection Platform has been tested using `pytest` and
`pytest-cov`.

Current test results:

- **189 tests passed**
- **95% overall code coverage**
- All core application modules have **100% coverage**

## Coverage Summary

The following major components have 100% test coverage:

- FastAPI application and API routers
- Alert repository
- Detection engine
- All detection rules
- Log parsers
- Timestamp handling
- Database initialization
- Normalization services
- Ingestion services
- MITRE ATT&CK mapping

## Intentionally Uncovered Code

A small number of lines remain uncovered.

### `app/detection/rule_base.py`

One line belongs to the abstract `evaluate()` method.

This method defines the interface that concrete detection rules must
implement. It is not expected to execute during normal application
operation because the concrete rule classes provide the implementations.

Therefore, this line is intentionally left uncovered.

### `app/parsers/cli_access_reader.py`

This module is a command-line wrapper around the access-log parsing
functionality.

The underlying parsing functionality is covered by the parser tests.
The CLI wrapper itself is not part of the main FastAPI application path
and is therefore intentionally not covered by the current automated test
suite.

### `app/parsers/cli_auth_reader.py`

This module is also a command-line wrapper around authentication-log
parsing functionality.

The underlying parser functionality is covered by tests. The CLI
entry-point wrapper is intentionally left uncovered because it is not
part of the main FastAPI application path.

## Test Philosophy

The goal of the test suite is not to achieve 100% coverage purely for
the sake of the coverage percentage.

Priority is given to testing:

1. Core application logic
2. Detection rules
3. API endpoints
4. Data persistence
5. Log parsing and normalization
6. Error and edge-case handling
7. Integration between major components

The remaining uncovered code consists of an abstract interface method
and CLI wrapper entry points rather than significant application logic.

## Test Command

Run the complete test suite with coverage using:

```bash
PYTHONPATH=. pytest --cov=app --cov-report=term-missing