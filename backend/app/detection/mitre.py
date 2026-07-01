"""A small MITRE ATT&CK technique catalog.

Detection rules and alerts carry a bare technique id like ``T1110``. This maps
those ids to a human-readable name and the ATT&CK tactic they belong to, so the
dashboard can show "Brute Force (Credential Access)" instead of a code, and so
we can report which tactics the deployed rules cover.

Only the techniques Argus actually references are required here; a handful of
neighbours are included so the catalog is useful as rules grow. Sub-technique
ids (``T1110.001``) fall back to their parent when not listed explicitly.
"""

from __future__ import annotations

from typing import NamedTuple


class Technique(NamedTuple):
    name: str
    tactic: str


CATALOG: dict[str, Technique] = {
    "T1110": Technique("Brute Force", "Credential Access"),
    "T1110.001": Technique("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": Technique("Brute Force: Password Spraying", "Credential Access"),
    "T1190": Technique("Exploit Public-Facing Application", "Initial Access"),
    "T1498": Technique("Network Denial of Service", "Impact"),
    "T1499": Technique("Endpoint Denial of Service", "Impact"),
    "T1046": Technique("Network Service Discovery", "Discovery"),
    "T1595": Technique("Active Scanning", "Reconnaissance"),
    "T1071": Technique("Application Layer Protocol", "Command and Control"),
    "T1078": Technique("Valid Accounts", "Defense Evasion"),
    "T1059": Technique("Command and Scripting Interpreter", "Execution"),
    "T1003": Technique("OS Credential Dumping", "Credential Access"),
}


def lookup(technique_id: str | None) -> Technique | None:
    """Resolve a technique id to its name and tactic.

    Falls back to the parent technique for an unknown sub-technique
    (``T1110.999`` -> ``T1110``); returns ``None`` if nothing matches.
    """
    if not technique_id:
        return None
    if technique_id in CATALOG:
        return CATALOG[technique_id]
    parent = technique_id.split(".")[0]
    return CATALOG.get(parent)
