"""Log-parsing framework.

Every parser turns a raw log line into a normalized :class:`ParsedEvent`. The
common fields (timestamp, source/dest IP, protocol) are promoted to columns for
indexing; everything else a parser extracts is preserved under ``raw`` so later
detection stages (M2+) can reason about it without re-parsing the line.

This is the principled replacement for the original project, which "detected"
attacks by counting lines of text pasted into a ``<textarea>``.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import SourceType


class ParsedEvent(BaseModel):
    """A normalized log event, ready to persist as an ``Event`` row."""

    timestamp: datetime
    source_ip: str | None = None
    dest_ip: str | None = None
    protocol: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class LogParser(ABC):
    """Base class for all log parsers."""

    source_type: SourceType

    @abstractmethod
    def parse_line(self, line: str) -> ParsedEvent | None:
        """Parse a single line, or return ``None`` if it isn't recognized."""

    def parse(self, text: str) -> Iterator[ParsedEvent]:
        """Parse a whole document, skipping blank and unrecognized lines."""
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            event = self.parse_line(line)
            if event is not None:
                yield event


_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_iso8601(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating ``+0000``-style offsets and ``Z``.

    Any timestamp lacking an explicit offset is assumed to be UTC.
    """
    normalized = _TZ_NO_COLON.sub(r"\1:\2", value.strip().replace("Z", "+00:00"))
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
