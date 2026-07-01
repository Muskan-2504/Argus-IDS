"""Tests for per-IP feature extraction."""

from datetime import UTC, datetime, timedelta

from app.detection.features import extract_features
from app.models.event import Event

BASE = datetime(2024, 10, 10, 13, 0, 0, tzinfo=UTC)


def _event(ip: str, offset: int, **raw: object) -> Event:
    return Event(timestamp=BASE + timedelta(seconds=offset), source_ip=ip, raw=raw)


def test_extract_features_basic() -> None:
    events = [
        _event("1.1.1.1", 0, outcome="failed"),
        _event("1.1.1.1", 30, outcome="failed"),
        _event("1.1.1.1", 60, outcome="accepted"),
        _event("2.2.2.2", 0, dest_port=22),
    ]
    feats = extract_features(events)
    assert set(feats) == {"1.1.1.1", "2.2.2.2"}

    one = feats["1.1.1.1"]
    assert one.count == 3
    assert one.failed_count == 2
    assert one.duration_seconds == 60.0
    assert one.rate_per_min == 3.0  # 3 events over 1 minute


def test_features_count_distinct_ports_and_errors() -> None:
    events = [_event("3.3.3.3", i, dest_port=1000 + i, status=500) for i in range(5)]
    feats = extract_features(events)["3.3.3.3"]
    assert feats.distinct_dest_ports == 5
    assert feats.error_count == 5
    assert len(feats.vector()) == 7


def test_extract_features_skips_events_without_ip() -> None:
    events = [Event(timestamp=BASE, source_ip=None, raw={})]
    assert extract_features(events) == {}
