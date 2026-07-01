"""Per-IP feature extraction for anomaly detection.

Both the statistical and ML detectors work from the same numeric features,
computed over a set of events grouped by source IP. Keeping extraction pure
and dependency-free makes it easy to unit-test and reuse.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from app.detection.definitions import get_field
from app.models.event import Event

_FAILED_OUTCOMES = {"failed", "invalid_user"}


@dataclass
class IpFeatures:
    source_ip: str
    count: int
    distinct_dest_ports: int
    distinct_paths: int
    distinct_user_agents: int
    failed_count: int
    error_count: int
    duration_seconds: float

    @property
    def rate_per_min(self) -> float:
        minutes = self.duration_seconds / 60.0
        return self.count / minutes if minutes > 0 else float(self.count)

    def vector(self) -> list[float]:
        """Numeric feature vector for the ML model."""
        return [
            float(self.count),
            float(self.distinct_dest_ports),
            float(self.distinct_paths),
            float(self.distinct_user_agents),
            float(self.failed_count),
            float(self.error_count),
            self.rate_per_min,
        ]


def extract_features(events: Iterable[Event]) -> dict[str, IpFeatures]:
    """Group events by source IP and compute per-IP features."""
    by_ip: dict[str, list[Event]] = {}
    for event in events:
        if event.source_ip:
            by_ip.setdefault(event.source_ip, []).append(event)

    features: dict[str, IpFeatures] = {}
    for ip, group in by_ip.items():
        timestamps = [e.timestamp for e in group]
        ports = {get_field(e, "raw.dest_port") for e in group} - {None}
        paths = {get_field(e, "raw.path") for e in group} - {None}
        agents = {get_field(e, "raw.user_agent") for e in group} - {None}
        failed = sum(1 for e in group if get_field(e, "raw.outcome") in _FAILED_OUTCOMES)
        errors = sum(
            1
            for e in group
            if isinstance(status := get_field(e, "raw.status"), int) and status >= 400
        )
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        features[ip] = IpFeatures(
            source_ip=ip,
            count=len(group),
            distinct_dest_ports=len(ports),
            distinct_paths=len(paths),
            distinct_user_agents=len(agents),
            failed_count=failed,
            error_count=errors,
            duration_seconds=duration,
        )
    return features
