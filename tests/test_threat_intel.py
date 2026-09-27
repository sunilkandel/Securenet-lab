"""
Tests for the AbuseIPDB client.

The HTTP call is mocked so these run offline. The important behaviours
are caching (one API call per IP per TTL) and graceful degradation when
the API key is missing or the API is down.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.models import ThreatIntel
from src.storage import Database
from src.threat_intel.threat_intel import ThreatIntelClient


@pytest.fixture
def db(tmp_path) -> Database:
    database = Database(tmp_path / "ti.db")
    yield database
    database.close()


def _mock_response(score: int = 85, status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": score,
            "countryCode": "RU",
            "isp": "Evil Hosting",
            "usageType": "Data Center/Web Hosting/Transit",
        }
    }
    return resp


def test_disabled_without_api_key(db):
    client = ThreatIntelClient(db, api_key="")
    assert client.enabled is False
    assert client.check("1.2.3.4") is None


@patch("src.threat_intel.threat_intel.requests.get")
def test_fetches_and_caches(mock_get, db):
    mock_get.return_value = _mock_response(90)
    client = ThreatIntelClient(db, api_key="test-key", cache_ttl=3600)

    first = client.check("1.2.3.4")
    assert first.abuse_confidence_score == 90
    assert first.country == "RU"

    second = client.check("1.2.3.4")
    assert second.abuse_confidence_score == 90
    # cache hit: still only one HTTP call
    assert mock_get.call_count == 1


@patch("src.threat_intel.threat_intel.requests.get")
def test_refreshes_stale_cache(mock_get, db):
    old = ThreatIntel(
        ip="1.2.3.4",
        abuse_confidence_score=10,
        last_checked=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    )
    db.upsert_threat_intel(old)

    mock_get.return_value = _mock_response(95)
    client = ThreatIntelClient(db, api_key="k", cache_ttl=60)
    result = client.check("1.2.3.4")
    assert result.abuse_confidence_score == 95
    assert mock_get.call_count == 1


@patch("src.threat_intel.threat_intel.requests.get")
def test_is_malicious_respects_threshold(mock_get, db):
    mock_get.return_value = _mock_response(80)
    client = ThreatIntelClient(db, api_key="k", min_score=50.0)
    assert client.is_malicious("1.2.3.4") is True


@patch("src.threat_intel.threat_intel.requests.get")
def test_below_threshold_not_malicious(mock_get, db):
    mock_get.return_value = _mock_response(20)
    client = ThreatIntelClient(db, api_key="k", min_score=50.0)
    assert client.is_malicious("1.2.3.4") is False


@patch("src.threat_intel.threat_intel.requests.get")
def test_graceful_on_api_error(mock_get, db):
    import requests
    mock_get.side_effect = requests.RequestException("connection reset")
    client = ThreatIntelClient(db, api_key="k")
    assert client.check("1.2.3.4") is None


@patch("src.threat_intel.threat_intel.requests.get")
def test_graceful_on_rate_limit(mock_get, db):
    mock_get.return_value = _mock_response(status=429)
    client = ThreatIntelClient(db, api_key="k")
    assert client.check("1.2.3.4") is None


@patch("src.threat_intel.threat_intel.requests.get")
def test_falls_back_to_stale_cache_on_failure(mock_get, db):
    stale = ThreatIntel(
        ip="1.2.3.4",
        abuse_confidence_score=42,
        last_checked=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
    )
    db.upsert_threat_intel(stale)
    import requests
    mock_get.side_effect = requests.RequestException("down")

    client = ThreatIntelClient(db, api_key="k", cache_ttl=60)
    result = client.check("1.2.3.4")
    assert result is not None
    assert result.abuse_confidence_score == 42


@patch("src.threat_intel.threat_intel.requests.get")
def test_private_ip_is_never_looked_up(mock_get, db):
    client = ThreatIntelClient(db, api_key="k")
    for ip in ["192.168.56.10", "10.0.0.1", "127.0.0.1", "::1", "not-an-ip"]:
        assert client.check(ip) is None
        assert client.is_malicious(ip) is False
    assert mock_get.call_count == 0


@patch("src.threat_intel.threat_intel.requests.get")
def test_zero_cache_ttl_always_refreshes(mock_get, db):
    mock_get.return_value = _mock_response(70)
    client = ThreatIntelClient(db, api_key="k", cache_ttl=0)
    client.check("1.2.3.4")
    client.check("1.2.3.4")
    assert mock_get.call_count == 2
