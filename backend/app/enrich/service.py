"""Enrichment orchestration: look up an IP's geo + reputation, cached in the
``ip_enrichment`` table so each address is resolved at most once.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy.orm import Session

from app.core.config import settings
from app.enrich.geoip import lookup_geo
from app.enrich.reputation import lookup_reputation
from app.models.enrichment import IpEnrichment


def enrichment_enabled() -> bool:
    """True when at least one provider is configured."""
    return bool(settings.geoip_db_path or settings.geoip_use_ipapi or settings.abuseipdb_api_key)


def enrich_ip(db: Session, ip: str) -> IpEnrichment | None:
    """Return cached enrichment for ``ip``, resolving it via the providers on a
    cache miss. Returns ``None`` when enrichment is disabled.
    """
    if not enrichment_enabled():
        return None
    cached = db.get(IpEnrichment, ip)
    if cached is not None:
        return cached

    geo = lookup_geo(ip)
    reputation = lookup_reputation(ip)
    record = IpEnrichment(
        ip=ip,
        country=geo.country if geo else None,
        city=geo.city if geo else None,
        latitude=geo.latitude if geo else None,
        longitude=geo.longitude if geo else None,
        abuse_score=reputation.abuse_score if reputation else None,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def enrich_ips(db: Session, ips: Iterable[str | None]) -> None:
    """Enrich each distinct, non-null IP (no-op when enrichment is disabled)."""
    if not enrichment_enabled():
        return
    for ip in {i for i in ips if i}:
        enrich_ip(db, ip)
