"""GeoIP lookups.

Two providers, both optional so the system runs with zero configuration:

* **MaxMind GeoLite2** — used when ``GEOIP_DB_PATH`` points at a ``.mmdb`` file
  (install the extra: ``pip install -e ".[geoip]"``). Offline and fast.
* **ip-api.com** — a free, key-less HTTP fallback, used only when
  ``GEOIP_USE_IPAPI=true`` so there are never surprise network calls.

When neither is configured, :func:`lookup_geo` returns ``None``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class GeoLocation:
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None


_reader = None  # cached MaxMind reader


def _maxmind(ip: str) -> GeoLocation | None:
    global _reader
    if _reader is None:
        try:
            import geoip2.database  # imported lazily; only needed with a DB
        except ImportError:
            logger.warning("GEOIP_DB_PATH set but geoip2 is not installed; skipping MaxMind.")
            return None
        _reader = geoip2.database.Reader(settings.geoip_db_path)
    try:
        response = _reader.city(ip)
    except Exception:  # noqa: BLE001 -- address not found / private range
        return None
    return GeoLocation(
        country=response.country.name,
        city=response.city.name,
        latitude=response.location.latitude,
        longitude=response.location.longitude,
    )


def _ipapi(ip: str) -> GeoLocation | None:
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon"},
            timeout=4.0,
        )
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    if data.get("status") != "success":
        return None
    return GeoLocation(
        country=data.get("country"),
        city=data.get("city"),
        latitude=data.get("lat"),
        longitude=data.get("lon"),
    )


def lookup_geo(ip: str) -> GeoLocation | None:
    if settings.geoip_db_path:
        return _maxmind(ip)
    if settings.geoip_use_ipapi:
        return _ipapi(ip)
    return None
