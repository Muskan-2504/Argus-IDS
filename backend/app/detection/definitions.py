"""Detection-rule definitions — the data model for Sigma-style rules.

Rules are **data, not code**. A rule is one of two shapes:

* :class:`MatchRule` — fires per event when a field matches a regex (e.g. a
  SQL-injection probe in a request path).
* :class:`ThresholdRule` — fires when events grouped by a key (usually the
  source IP) exceed a count within a time window — optionally counting
  *distinct* values of a field (a port scan = many distinct destination
  ports). This replaces the original project's hard-coded ``if`` heuristics.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, PrivateAttr, TypeAdapter

from app.models.enums import Severity


def get_field(obj: Any, path: str) -> Any:
    """Resolve a dotted ``path`` against an event, descending into ``raw``.

    ``source_ip`` reads the column; ``raw.outcome`` reads ``event.raw['outcome']``.
    """
    parts = path.split(".")
    value = getattr(obj, parts[0], None)
    for part in parts[1:]:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def selection_matches(obj: Any, selection: dict[str, Any]) -> bool:
    """True if every ``path: expected`` in ``selection`` matches the event.

    A list ``expected`` means "value is one of"; a scalar means equality.
    """
    for path, expected in selection.items():
        actual = get_field(obj, path)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


class _BaseRule(BaseModel):
    key: str
    name: str
    description: str | None = None
    severity: Severity = Severity.medium
    mitre_technique: str | None = None
    enabled: bool = True


class MatchRule(_BaseRule):
    """Per-event regex match against a single field."""

    type: Literal["match"] = "match"
    selection: dict[str, Any] = Field(default_factory=dict)
    field: str
    patterns: list[str] = Field(min_length=1)
    decode: Literal["url"] | None = None

    _compiled: list[re.Pattern[str]] = PrivateAttr(default_factory=list)

    def model_post_init(self, _context: Any) -> None:
        self._compiled = [re.compile(p) for p in self.patterns]

    @property
    def compiled(self) -> list[re.Pattern[str]]:
        return self._compiled


class ThresholdRule(_BaseRule):
    """Windowed aggregation: count (or distinct-count) per group key."""

    type: Literal["threshold"] = "threshold"
    selection: dict[str, Any] = Field(default_factory=dict)
    group_by: str = "source_ip"
    window_seconds: int = Field(gt=0)
    threshold: int = Field(ge=1)
    distinct_field: str | None = None


RuleDefinition = Annotated[MatchRule | ThresholdRule, Field(discriminator="type")]

rule_adapter: TypeAdapter[MatchRule | ThresholdRule] = TypeAdapter(RuleDefinition)
