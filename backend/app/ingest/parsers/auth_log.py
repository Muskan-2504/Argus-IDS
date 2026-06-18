"""Parser for Linux ``/var/log/auth.log`` SSH authentication lines.

Recognizes the three lines that matter for brute-force detection::

    Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2
    Failed password for root from 203.0.113.5 port 54322 ssh2
    Accepted password for alice from 10.0.0.5 port 53210 ssh2

The classic syslog timestamp carries no year, so an optional reference year may
be supplied (defaulting to the current year) to build a full datetime.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from app.ingest.parsers.base import LogParser, ParsedEvent
from app.models.enums import SourceType

# "Jan 10 13:55:36 host sshd[1234]: <message>"
_LINE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
_FAILED = re.compile(
    r"^Failed password for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)")


class AuthLogParser(LogParser):
    source_type = SourceType.auth_log

    def __init__(self, year: int | None = None) -> None:
        self._year = year if year is not None else datetime.now(UTC).year

    def _timestamp(self, raw_ts: str) -> datetime:
        # Collapse the variable whitespace in "Jan  1" before strptime.
        compact = re.sub(r"\s+", " ", raw_ts.strip())
        naive = datetime.strptime(f"{self._year} {compact}", "%Y %b %d %H:%M:%S")
        return naive.replace(tzinfo=UTC)

    def parse_line(self, line: str) -> ParsedEvent | None:
        match = _LINE.match(line)
        if not match:
            return None
        timestamp = self._timestamp(match.group("ts"))
        message = match.group("msg")

        if failed := _FAILED.match(message):
            outcome = "invalid_user" if failed.group("invalid") else "failed"
            return self._event(timestamp, failed, outcome)
        if accepted := _ACCEPTED.match(message):
            return self._event(timestamp, accepted, "accepted")
        if invalid := _INVALID.match(message):
            return ParsedEvent(
                timestamp=timestamp,
                source_ip=invalid.group("ip"),
                protocol="ssh",
                raw={"outcome": "invalid_user", "username": invalid.group("user")},
            )
        return None

    @staticmethod
    def _event(timestamp: datetime, match: re.Match[str], outcome: str) -> ParsedEvent:
        return ParsedEvent(
            timestamp=timestamp,
            source_ip=match.group("ip"),
            protocol="ssh",
            raw={
                "outcome": outcome,
                "username": match.group("user"),
                "source_port": int(match.group("port")),
                "service": "sshd",
            },
        )
