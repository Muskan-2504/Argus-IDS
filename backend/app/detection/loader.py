"""Load and validate detection rules from the YAML files in ``rules/``."""

from __future__ import annotations

from pathlib import Path

import yaml

from app.detection.definitions import MatchRule, ThresholdRule, rule_adapter

RULES_DIR = Path(__file__).parent / "rules"


def load_rules(directory: Path | None = None) -> list[MatchRule | ThresholdRule]:
    """Parse every ``*.yml`` file in ``directory`` into a validated rule."""
    directory = directory or RULES_DIR
    rules: list[MatchRule | ThresholdRule] = []
    for path in sorted(directory.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(rule_adapter.validate_python(data))
    return rules


def load_enabled_rules(directory: Path | None = None) -> list[MatchRule | ThresholdRule]:
    """Like :func:`load_rules` but skips rules marked ``enabled: false``."""
    return [rule for rule in load_rules(directory) if rule.enabled]
