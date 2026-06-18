"""Parser for Suricata EVE JSON logs (one JSON object per line)::

    {"timestamp":"2024-10-10T13:55:36.123456+0000","event_type":"alert",
     "src_ip":"203.0.113.5","src_port":54321,"dest_ip":"10.0.0.5","dest_port":22,
     "proto":"TCP","alert":{"signature":"ET SCAN Potential SSH Scan","severity":2}}

Suricata has already classified the traffic, so its alert metadata (signature,
category, severity) is carried straight through into ``raw`` for correlation.
"""

from __future__ import annotations

import json
from typing import Any

from app.ingest.parsers.base import LogParser, ParsedEvent, parse_iso8601
from app.models.enums import SourceType


class SuricataParser(LogParser):
    source_type = SourceType.suricata

    def parse_line(self, line: str) -> ParsedEvent | None:
        try:
            record: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            return None
        if "timestamp" not in record:
            return None

        raw: dict[str, Any] = {
            "event_type": record.get("event_type"),
            "src_port": record.get("src_port"),
            "dest_port": record.get("dest_port"),
            "app_proto": record.get("app_proto"),
        }
        if isinstance(alert := record.get("alert"), dict):
            raw["alert"] = {
                "signature": alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                "category": alert.get("category"),
                "severity": alert.get("severity"),
            }

        return ParsedEvent(
            timestamp=parse_iso8601(record["timestamp"]),
            source_ip=record.get("src_ip"),
            dest_ip=record.get("dest_ip"),
            protocol=(record.get("proto") or "").lower() or None,
            raw=raw,
        )
