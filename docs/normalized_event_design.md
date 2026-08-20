# NormalizedEvent Design

## Purpose

`NormalizedEvent` provides a common schema for events from different log sources.

The detection engine will consume `NormalizedEvent` objects instead of depending directing on source-specific event models such as `AuthLogEvent` or `AccessLogEvent`

## Fields

| Field | Type | Description |
|-------|------|-------------|
| event_id | str | Unique identifier for the normalized event |
| timestamp | datetime | Time when the event occurred |
| source_type | str | Source of the event, such as `auth` or `apache`|
| source_ip | str\| None | Source IP address when available |
| username | str\| None |Username associated with the event when available |
| raw_event_type | str | Original event type or classification |
| raw_data | dict | Original Structured event data |

## Design 

Source-specific events are normalized into one common structure:

```text 
AuthLogEvent
           |
           |
          \|/
    NormalizedEvent
          /|\
           |
           |
AccessLogEvent