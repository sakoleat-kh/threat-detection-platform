"""date model for Apache/Nginx ccess-log events."""

from dataclasses import dataclass

@dataclass
class AccessLogEvent:
    client_ip: str
    remote_logname: str
    authenticated_user: str
    timestamp: str
    request: str
    status_code: int
    response_size: int
    referre: str
    user_agent: str