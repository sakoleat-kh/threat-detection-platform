"""Parse Apache/Nginx Combined Log Format access-log entries."""

import re
from datetime import datetime
from typing import Optional

from app.models.access_event import AccessLogEvent

CLF_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+'
    r'(?P<remote_logname>\S+)\s+'
    r'(?P<authenticated_user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status_code>\d{3})\s+'
    r'(?P<response_size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"\s+'
    r'"[^"]*"$'
)

def parse_access_line(raw_line: str) -> Optional[AccessLogEvent]:
    """Parse one Apache Combined Log Format line."""

    match = CLF_PATTERN.match(raw_line.rstrip("\n"))

    if not match:
        return None

    data = match.groupdict()
    request = data["request"]
    request_parts = request.split(" ", 2)

    if len(request_parts) != 3:
        return None

    method, path, protocol = request_parts

    timestamp = datetime.strptime(
        data["timestamp"],
        "%d/%b/%Y:%H:%M:%S %z",
    )

    return AccessLogEvent(
        client_ip=data["client_ip"],
        remote_logname=data["remote_logname"],
        authenticated_user=data["authenticated_user"],
        timestamp=timestamp,
        request=request,
        method=method,
        path=path,
        protocol=protocol,
        status_code=int(data["status_code"]),
        response_size=int(data["response_size"]),
        referer=data["referer"],
        user_agent=data["user_agent"],
    )