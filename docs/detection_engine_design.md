# Detection Engine Desin

## Purpose

The detection engine evaluates normalized security events using independent detection rules.

Source-specific events are first converted into `NormalizedEvent` objects.

## Architecture

```text
AuthLogEvent ------
                  |
                  |
                 \|/
            Normalizer
                  |
                  |
AuthLogEvent ------
                  |
                  |
                 \|/
            NormalizedEvent
                  |
                  |
                 \|/
            Detection Engine
                  |
                  |
                  |
    ------------------------------
    |             |              |
   \|/           \|/            \|/
  Rule 1       Rule 2           Rule 3
    |             |              |
    |             |              |
    ------------------------------
                  |
                 \|/
                Alerts
