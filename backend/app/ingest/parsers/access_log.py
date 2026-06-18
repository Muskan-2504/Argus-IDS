"""Parser for the NCSA *combined* access-log format used by both nginx and
Apache::

    203.0.113.5 - - [10/Oct/2024:13:55:36 +0000] "GET /admin HTTP/1.1" 404 153 "-" "curl/7.68"

Extracts the request line, status, and user-agent. The request path is kept in
``raw`` so the M2 rule engine can scan it for SQL-injection / path-traversal
probes, and the status code feeds error-rate anomaly detection.
"""

from __future__ import annotations

import re
from datetime import datetime

from app.ingest.parsers.base import LogParser, ParsedEvent
from app.models.enums import SourceType

_LINE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" '
    r"(?P<status>\d{3}) (?P<size>\d+|-)"
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)


class AccessLogParser(LogParser):
    """Handles nginx and Apache combined/common log lines."""

    source_type = SourceType.nginx

    def parse_line(self, line: str) -> ParsedEvent | None:
        match = _LINE.match(line)
        if not match:
            return None
        timestamp = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
        size = match.group("size")
        return ParsedEvent(
            timestamp=timestamp,
            source_ip=match.group("ip"),
            protocol="http",
            raw={
                "method": match.group("method"),
                "path": match.group("path"),
                "http_version": match.group("proto"),
                "status": int(match.group("status")),
                "size": None if size == "-" else int(size),
                "referer": match.group("referer"),
                "user_agent": match.group("agent"),
            },
        )
