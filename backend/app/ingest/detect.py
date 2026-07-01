"""Best-effort detection of a raw log's format.

The paste-your-logs UI lets non-technical users analyze logs without first
having to know whether they're staring at syslog, an NCSA access log, or
Suricata EVE JSON. :func:`sniff_source_type` inspects the first handful of
non-blank lines and returns the matching :class:`SourceType`, or ``None`` when
nothing recognizable turns up (so the caller can ask the user to pick).

The heuristics are deliberately conservative — a confident match on a known
shape, never a guess — because mis-detecting the format silently drops every
line as unparseable.
"""

from __future__ import annotations

import json
import re

from app.models.enums import SourceType

# "<...> sshd[1234]: <message>" — the syslog signature of an auth.log line.
_SSHD = re.compile(r"\bsshd\[\d+\]:\s")

# NCSA combined: 'IP - - [date] "METHOD path proto" status size ...'
_ACCESS = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[A-Z]+ \S+ [^"]+" \d{3} ')

# Only sniff the head of the input; a real log is homogeneous, so the first few
# lines settle the format without scanning a multi-megabyte paste.
_MAX_LINES = 25


def sniff_source_type(text: str) -> SourceType | None:
    """Guess the log format of ``text``, or return ``None`` if unrecognized."""
    inspected = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Suricata EVE JSON: one JSON object per line carrying network fields.
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = None
            if isinstance(record, dict) and (
                "event_type" in record or "src_ip" in record or "flow_id" in record
            ):
                return SourceType.suricata

        if _SSHD.search(line):
            return SourceType.auth_log
        if _ACCESS.match(line):
            return SourceType.nginx  # nginx/apache share the combined format

        inspected += 1
        if inspected >= _MAX_LINES:
            break

    return None
