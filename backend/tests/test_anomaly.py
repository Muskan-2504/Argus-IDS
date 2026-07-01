"""Tests for the statistical and ML anomaly detectors."""

from datetime import UTC, datetime, timedelta

from app.detection.anomaly import ml_anomalies, statistical_anomalies
from app.detection.features import extract_features
from app.models.event import Event

BASE = datetime(2024, 10, 10, 13, 0, 0, tzinfo=UTC)


def _events(ip: str, count: int, **raw: object) -> list[Event]:
    return [
        Event(timestamp=BASE + timedelta(seconds=i), source_ip=ip, raw=dict(raw))
        for i in range(count)
    ]


def test_statistical_flags_volume_outlier() -> None:
    events: list[Event] = []
    for n in range(8):  # eight quiet peers
        events += _events(f"10.0.0.{n}", 4)
    events += _events("203.0.113.9", 40)  # one loud outlier

    findings = statistical_anomalies(extract_features(events))
    flagged = {f.source_ip for f in findings}
    assert "203.0.113.9" in flagged
    assert not flagged & {f"10.0.0.{n}" for n in range(8)}


def test_statistical_quiet_population_is_silent() -> None:
    events: list[Event] = []
    for n in range(6):
        events += _events(f"10.0.0.{n}", 5)
    assert statistical_anomalies(extract_features(events)) == []


def test_ml_flags_behavioral_outlier() -> None:
    events: list[Event] = []
    # Ten similar "normal" IPs: a few requests, one path.
    for n in range(10):
        events += _events(f"10.0.0.{n}", 5, path="/", status=200)
    # One IP that scans many ports — a clear behavioral outlier.
    events += [
        Event(timestamp=BASE + timedelta(seconds=i), source_ip="203.0.113.50", raw={"dest_port": p})
        for i, p in enumerate(range(40))
    ]

    findings = ml_anomalies(extract_features(events))
    assert "203.0.113.50" in {f.source_ip for f in findings}


def test_ml_too_few_samples_returns_empty() -> None:
    events = _events("1.1.1.1", 5)
    assert ml_anomalies(extract_features(events)) == []
