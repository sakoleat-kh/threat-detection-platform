# AccessLogEvent Design

## Purpose

`AccessLogEvent` represents one Apache/Nginx Combined Log Format access-log entry.

The model stores the nine fields extracted from each access-log line.

## Fields

| Field | Type | Description |
|---|---|---|
| client_ip | str | IP address of the client making the request |
| remote_logname | str | Remote logname, usually `-` |
| authenticated_user | str | Authenticated username, or `-` |
| timestamp | str | Date and time of the request |
| request | str | Complete HTTP request line |
| status_code | int | HTTP response status code |
| response_size | int | Response size in bytes |
| referer | str | Referring URL, or `-` |
| user_agent | str | Browser, crawler, or client software |