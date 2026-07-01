"""Tests for the enrichment service (caching + graceful disable)."""

import pytest
from sqlalchemy.orm import Session

import app.enrich.service as svc
from app.enrich.geoip import GeoLocation
from app.enrich.reputation import Reputation


def test_enrich_disabled_returns_none(db_session: Session) -> None:
    # No providers configured by default.
    assert svc.enrich_ip(db_session, "203.0.113.5") is None


def test_enrich_resolves_and_caches(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc.settings, "geoip_use_ipapi", True)
    calls = {"geo": 0, "rep": 0}

    def fake_geo(_ip: str) -> GeoLocation:
        calls["geo"] += 1
        return GeoLocation(country="Testland", city="Test City", latitude=1.5, longitude=2.5)

    def fake_rep(_ip: str) -> Reputation:
        calls["rep"] += 1
        return Reputation(abuse_score=42)

    monkeypatch.setattr(svc, "lookup_geo", fake_geo)
    monkeypatch.setattr(svc, "lookup_reputation", fake_rep)

    first = svc.enrich_ip(db_session, "203.0.113.5")
    assert first is not None
    assert first.country == "Testland"
    assert first.latitude == 1.5
    assert first.abuse_score == 42

    # Second lookup is served from cache — providers are not called again.
    second = svc.enrich_ip(db_session, "203.0.113.5")
    assert second is not None
    assert second.ip == "203.0.113.5"
    assert calls == {"geo": 1, "rep": 1}
