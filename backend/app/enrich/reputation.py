"""IP reputation via AbuseIPDB (optional — only runs when an API key is set)."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.core.config import settings


@dataclass
class Reputation:
    abuse_score: int | None = None  # AbuseIPDB confidence-of-abuse, 0–100


def lookup_reputation(ip: str) -> Reputation | None:
    if not settings.abuseipdb_api_key:
        return None
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=4.0,
        )
        data = resp.json()["data"]
    except (httpx.HTTPError, ValueError, KeyError):
        return None
    return Reputation(abuse_score=data.get("abuseConfidenceScore"))
