# AuthLogEvent Design

## Purpose

`AuthLogEvent` represents one authentication-related event parsed from a Linux `auth.log` line.

The parser will eventually convert a raw log line into this structured event so that detection rules can work with consistent fileds.


## Fields 

| Field | Type | Optional | Purpose |

| `raw_line` | `str` | No | The original log line |
| `timestamp` | `str ` | No | Date and time of the event |
| `host` | `str ` | No | Hostname that generated the event |
| `process` | `str` | No | Process that generated the event |
| `pid` | `str` | Yes | Process ID, when availale |
| `event_type` | `EventType` | No | Classification of the authentication event | 
| `username` | `str` | Yes | Username involved in the event |
| `source_ip` | `str` | Yes | Source IP address, when availale |
| `port` | `int` | Yes | Source port, when available |

## Event Types

The supported event types are:
- `SSH_FAILED_PASSWORD`
- `SSH_ACCEPTED_PASSWOED`
- `SSH_INVALID_USER`
- `SUDO_COMMAND`
- `SUDO_AUTH_FAILURE`
- `USER_ADDED`
- `UNKNOWN`

## Design Noted

Some authentication events do not contain every field.

For example, a `sudo` event may not contain a source IP or network port.

Therefore. `pid`, `username`, `source_ip`, and `port` are optional.

`event_type` uses an Enum instead of arbitrary string so that the application has a fixed and consistent set of event classifications.