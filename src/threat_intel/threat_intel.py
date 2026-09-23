"""
Threat intelligence via the AbuseIPDB API.

Answers one question: "how bad is this IP?" Results are cached in the
SQLite database, so a noisy IP costs one API call per cache_ttl seconds
instead of one per event. AbuseIPDB's free tier allows 1000 checks a
day, and caching is what keeps a brute-force storm under that limit.

If no API key is configured the module degrades quietly: lookups return
None, the pipeline keeps working, and the auto-ban still fires on local
detection alone.

Private, loopback and other non-public addresses are never looked up:
AbuseIPDB has no data on them, so in the lab (all 192.168.56.x) a
lookup would only burn the daily quota.
"""

from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone

import requests

from src.config import settings
from src.logging_setup import get_logger
from src.models import ThreatIntel
from src.storage import Database

log = get_logger(__name__)

_API_URL = "https://api.abuseipdb.com/api/v2/check"


def _is_public(ip: str) -> bool:
    """True for globally routable addresses (worth asking AbuseIPDB)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class ThreatIntelClient:
    """AbuseIPDB lookup with a persistent cache."""

    def __init__(
        self,
        db: Database,
        api_key: str | None = None,
        cache_ttl: int | None = None,
        timeout: float = 5.0,
        min_score: float | None = None,
    ) -> None:
        self.db = db
        self.api_key = api_key if api_key is not None else settings.abuseipdb_api_key
        # `is None`, not `or`: 0 is a valid TTL (always refresh)
        self.cache_ttl = (
            settings.abuseipdb_cache_ttl if cache_ttl is None else cache_ttl
        )
        self.timeout = timeout
        # Snapshotted so tests can pass an explicit threshold rather
        # than patching the frozen settings singleton.
        self.min_score = (
            settings.abuseipdb_min_score if min_score is None else min_score
        )

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def check(self, ip: str) -> ThreatIntel | None:
        """Return threat intel for *ip*, from cache or the API.

        Returns None when the API key is missing or the request fails.
        Cache entries older than cache_ttl are refreshed.
        """
        if not _is_public(ip):
            return None

        cached = self.db.get_threat_intel(ip)
        if cached and not self._is_stale(cached):
            return cached

        if not self.enabled:
            return cached  # may be None; pipeline continues either way

        intel = self._fetch(ip)
        if intel is not None:
            self.db.upsert_threat_intel(intel)
            return intel
        # API failed; fall back to stale cache rather than nothing
        return cached

    def is_malicious(self, ip: str) -> bool:
        """True when the IP's abuse score meets the configured threshold."""
        intel = self.check(ip)
        if intel is None:
            return False
        return intel.abuse_confidence_score >= self.min_score

    # -- internals -------------------------------------------------------------

    def _is_stale(self, intel: ThreatIntel) -> bool:
        try:
            checked = datetime.fromisoformat(intel.last_checked)
            if checked.tzinfo is None:
                checked = checked.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - checked).total_seconds()
            return age > self.cache_ttl
        except ValueError:
            return True

    def _fetch(self, ip: str) -> ThreatIntel | None:
        try:
            resp = requests.get(
                _API_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            log.warning("AbuseIPDB request failed for %s: %s", ip, exc)
            return None

        if resp.status_code == 429:
            log.warning("AbuseIPDB rate limit hit; backing off")
            time.sleep(2)
            return None
        if resp.status_code != 200:
            log.warning("AbuseIPDB returned %s for %s", resp.status_code, ip)
            return None

        try:
            data = resp.json().get("data", {})
        except ValueError:
            log.warning("AbuseIPDB returned non-JSON for %s", ip)
            return None

        return ThreatIntel(
            ip=ip,
            abuse_confidence_score=float(data.get("abuseConfidenceScore", 0)),
            country=data.get("countryCode", ""),
            isp=data.get("isp", ""),
            usage_type=data.get("usageType", ""),
            lookup_result=data,
        )
