"""Data model for Apache/Nginx access-log events."""

from dataclasses import dataclass
from datetime import datetime

@dataclass
class AccessLogEvent:
    client_ip: str
    remote_logname: str
    authenticated_user: str
    timestamp: datetime
    request: str
    method: str
    path: str
    query_string: str
    protocol: str
    status_code: int
    response_size: int
    referer: str
    user_agent: str