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

## Rule 4 - New User Creation

The New User Creation rule generates an alert for every `USER_ADDED` event.

UID filtering is intentionally not applied. In particular, users with UIDs below 1000 are not automatically ignored. The design treats every new user creation as security-relevant and leaves the decision about whether the account is legitimate to further investigation.
