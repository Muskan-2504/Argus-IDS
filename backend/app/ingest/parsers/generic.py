"""A best-effort parser for arbitrary / unknown log formats.

Where the format-specific parsers (auth.log, access log, Suricata) demand an
exact shape, this one *extracts* the fields that matter for detection out of
whatever it is handed — a JSON object, ``key=value`` (logfmt) pairs, or plain
free text — so a user can paste a log Argus has never seen and still get IPs,
ports, request paths, and auth outcomes pulled out for the rule engine.

The guiding idea (and the user's ask): don't insist on a format, *find the key
values that matter*. Structured data (JSON/logfmt) is trusted first; free-text
regex extraction fills the gaps. A non-blank line is never dropped — anything
unclassified is still kept under ``raw.message``. Lines without their own
timestamp are stamped at ingest time so a pasted burst still clusters into one
detection window.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from app.ingest.parsers.base import LogParser, ParsedEvent, parse_iso8601
from app.models.enums import SourceType

# Canonical field <- the leaf key names (lowercased, '-'/' ' -> '_') that carry
# it across the log formats we've seen in the wild.
_SRC_IP_KEYS = {
    "src_ip",
    "source_ip",
    "sourceip",
    "client_ip",
    "clientip",
    "remote_addr",
    "remote_ip",
    "c_ip",
    "cip",
    "ip",
    "src",
    "source",
    "client",
    "remote",
}
_DST_IP_KEYS = {"dest_ip", "dst_ip", "destip", "destination_ip", "server_ip", "dst", "destination"}
_DST_PORT_KEYS = {"dest_port", "dst_port", "dstport", "destination_port", "port", "dport"}
_TS_KEYS = {
    "timestamp",
    "@timestamp",
    "time",
    "datetime",
    "date",
    "eventtime",
    "event_time",
    "_time",
    "ts",
}
_PROTO_KEYS = {"proto", "protocol", "transport", "app_proto"}
_PATH_KEYS = {"path", "url", "uri", "request", "request_uri", "uri_stem", "cs_uri_stem"}
_METHOD_KEYS = {"method", "verb", "request_method", "cs_method"}
_STATUS_KEYS = {"status", "status_code", "statuscode", "response", "sc_status", "response_code"}
_USER_KEYS = {"user", "username", "user_name", "account", "userid", "uid", "cs_username"}
_OUTCOME_KEYS = {"outcome", "result", "action", "event_outcome", "auth_result"}

_IPV4_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
_IPV4 = re.compile(rf"\b{_IPV4_RE}\b")
_FROM_IP = re.compile(rf"\bfrom\s+({_IPV4_RE})\b", re.IGNORECASE)
_TO_IP = re.compile(rf"\bto\s+({_IPV4_RE})\b", re.IGNORECASE)
_HTTP_REQ = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[0-9.]+"')
_HTTP_STATUS = re.compile(r'"\s+(\d{3})\b')
_FAIL_WORDS = re.compile(
    r"(?i)\b(fail|failed|failure|invalid|denied|deny|unauthor\w*|reject\w*|error)\b"
)
# Each known protocol token, matched on a leading word boundary so "sshd"/"ssh2"
# still resolve to "ssh".
_PROTO_TOKENS = ("https", "http", "ssh", "tcp", "udp", "dns", "ftp", "smtp")

_ISO_TS = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)
_NCSA_TS = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]")
_SYSLOG_TS = re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
_LOGFMT = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\S+)')


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts/lists into dotted scalar keys."""
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}{key}"
            if isinstance(value, dict | list):
                out.update(_flatten(value, f"{path}."))
            else:
                out[path] = value
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            out.update(_flatten(value, f"{prefix}{i}."))
    return out


def _try_logfmt(line: str) -> dict[str, Any]:
    """Parse ``key=value`` pairs; returns {} unless at least two are present."""
    pairs = _LOGFMT.findall(line)
    if len(pairs) < 2:
        return {}
    fields: dict[str, Any] = {}
    for key, value in pairs:
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        fields[key] = value
    return fields


def _pick(fields: dict[str, Any], keys: set[str]) -> Any:
    """Return the first value whose (dotted) leaf key is one of ``keys``."""
    for full_key, value in fields.items():
        leaf = full_key.split(".")[-1].lower().replace("-", "_").replace(" ", "_")
        if leaf in keys and value not in (None, ""):
            return value
    return None


def _coerce_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _clean_ip(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _parse_ts(value: Any) -> datetime | None:
    """Parse a structured timestamp: ISO-8601 string or epoch seconds/millis."""
    if isinstance(value, str):
        try:
            return parse_iso8601(value)
        except ValueError:
            return None
    if isinstance(value, int | float):
        seconds = float(value)
        if seconds > 1e12:  # looks like epoch milliseconds
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OSError, ValueError, OverflowError):
            return None
    return None


def _extract_ts(line: str) -> datetime | None:
    """Find and parse the first timestamp embedded in a free-text line."""
    if iso := _ISO_TS.search(line):
        try:
            return parse_iso8601(iso.group(1))
        except ValueError:
            pass
    if ncsa := _NCSA_TS.search(line):
        try:
            return datetime.strptime(ncsa.group(1), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            pass
    if syslog := _SYSLOG_TS.search(line):
        compact = re.sub(r"\s+", " ", syslog.group(1))
        try:
            year = datetime.now(UTC).year
            return datetime.strptime(f"{year} {compact}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def _extract_freetext(line: str) -> dict[str, Any]:
    """Pull detection-relevant entities out of an unstructured line."""
    out: dict[str, Any] = {}

    if m := _FROM_IP.search(line):
        out["source_ip"] = m.group(1)
    if m := _TO_IP.search(line):
        out["dest_ip"] = m.group(1)
    if "source_ip" not in out:
        ips = [ip for ip in _IPV4.findall(line) if _valid_ipv4(ip)]
        if ips:
            out["source_ip"] = ips[0]
            if "dest_ip" not in out and len(ips) > 1:
                out["dest_ip"] = ips[1]

    if req := _HTTP_REQ.search(line):
        out["protocol"] = "http"
        out["method"] = req.group("method")
        out["path"] = req.group("path")
        if status := _HTTP_STATUS.search(line):
            out["status"] = int(status.group(1))

    if "protocol" not in out:
        lowered = line.lower()
        for token in _PROTO_TOKENS:
            if re.search(rf"\b{token}", lowered):
                out["protocol"] = "http" if token == "https" else token
                break

    if _FAIL_WORDS.search(line):
        out["outcome"] = "failed"

    if ts := _extract_ts(line):
        out["timestamp"] = ts

    return out


class GenericParser(LogParser):
    """Format-agnostic parser: extracts key fields from any log line."""

    source_type = SourceType.custom

    def parse_line(self, line: str) -> ParsedEvent | None:
        structured = self._structured_fields(line)
        text = _extract_freetext(line)

        def field(canonical: set[str], text_key: str | None = None) -> Any:
            value = _pick(structured, canonical)
            if value is None and text_key is not None:
                value = text.get(text_key)
            return value

        protocol = field(_PROTO_KEYS, "protocol")
        timestamp = (
            _parse_ts(_pick(structured, _TS_KEYS)) or text.get("timestamp") or datetime.now(UTC)
        )

        raw: dict[str, Any] = {}
        _set(raw, "outcome", field(_OUTCOME_KEYS, "outcome"))
        _set(raw, "dest_port", _coerce_int(_pick(structured, _DST_PORT_KEYS)))
        _set(raw, "path", field(_PATH_KEYS, "path"))
        _set(raw, "method", field(_METHOD_KEYS, "method"))
        _set(raw, "status", _coerce_int(field(_STATUS_KEYS, "status")))
        _set(raw, "username", _pick(structured, _USER_KEYS))
        if structured:
            raw["fields"] = structured
        else:
            raw["message"] = line

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=_clean_ip(field(_SRC_IP_KEYS, "source_ip")),
            dest_ip=_clean_ip(field(_DST_IP_KEYS, "dest_ip")),
            protocol=protocol.lower() if isinstance(protocol, str) else None,
            raw=raw,
        )

    @staticmethod
    def _structured_fields(line: str) -> dict[str, Any]:
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                return _flatten(obj)
        return _try_logfmt(line)


def _set(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        target[key] = value
