"""Tests for the core data models."""

import json

import pytest

from src.models import (
    Event,
    EventType,
    Severity,
    IPInfo,
    Ban,
    BanStatus,
    ThreatIntel,
    Alert,
    AlertChannel,
    AlertStatus,
    _utcnow,
)


# ---------------------------------------------------------------------------
# Enum Tests
# ---------------------------------------------------------------------------

class TestEnums:
    def test_severity_values(self):
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_event_type_values(self):
        assert EventType.SSH_BRUTE_FORCE.value == "ssh_brute_force"
        assert EventType.PORT_SCAN.value == "port_scan"
        assert EventType.WEB_ENUMERATION.value == "web_enumeration"
        assert EventType.UNKNOWN.value == "unknown"

    def test_alert_channel_values(self):
        assert AlertChannel.TELEGRAM.value == "telegram"
        assert AlertChannel.EMAIL.value == "email"

    def test_alert_status_values(self):
        assert AlertStatus.PENDING.value == "pending"
        assert AlertStatus.SENT.value == "sent"
        assert AlertStatus.FAILED.value == "failed"

    def test_ban_status_values(self):
        assert BanStatus.ACTIVE.value == "active"
        assert BanStatus.EXPIRED.value == "expired"
        assert BanStatus.REMOVED.value == "removed"

    def test_enums_are_str_subclasses(self):
        """Enums should be usable as plain strings."""
        assert Severity.HIGH == "high"
        assert EventType.PORT_SCAN == "port_scan"


# ---------------------------------------------------------------------------
# Event Tests
# ---------------------------------------------------------------------------

class TestEvent:
    def _make_event(self, **overrides) -> Event:
        defaults = dict(
            source_ip="192.168.56.10",
            event_type=EventType.SSH_BRUTE_FORCE,
            severity=Severity.HIGH,
            raw_log="Failed password for root from 192.168.56.10 port 22 ssh2",
            mitre_technique="T1110",
            details={"attempts": 12, "user": "root"},
        )
        defaults.update(overrides)
        return Event(**defaults)

    def test_creation(self):
        e = self._make_event()
        assert e.source_ip == "192.168.56.10"
        assert e.event_type == EventType.SSH_BRUTE_FORCE
        assert e.severity == Severity.HIGH
        assert e.mitre_technique == "T1110"
        assert e.details["attempts"] == 12
        assert e.id is None

    def test_timestamps_auto_populated(self):
        e = self._make_event()
        assert e.timestamp != ""
        assert e.created_at != ""

    def test_to_dict(self):
        e = self._make_event(id=42)
        d = e.to_dict()
        assert d["source_ip"] == "192.168.56.10"
        assert d["event_type"] == "ssh_brute_force"
        assert d["severity"] == "high"
        assert d["id"] == 42
        assert d["details"]["attempts"] == 12
        # Should be a plain dict, no enums left
        assert isinstance(d["event_type"], str)
        assert isinstance(d["severity"], str)

    def test_to_json(self):
        e = self._make_event()
        raw = e.to_json()
        parsed = json.loads(raw)
        assert parsed["source_ip"] == "192.168.56.10"
        assert parsed["event_type"] == "ssh_brute_force"

    def test_from_dict(self):
        original = self._make_event(id=7)
        d = original.to_dict()
        restored = Event.from_dict(d)
        assert restored.source_ip == original.source_ip
        assert restored.event_type == original.event_type
        assert restored.severity == original.severity
        assert restored.id == 7
        assert restored.details == original.details

    def test_from_json(self):
        original = self._make_event()
        raw = original.to_json()
        restored = Event.from_json(raw)
        assert restored.source_ip == original.source_ip
        assert restored.event_type == original.event_type

    def test_roundtrip_dict(self):
        """to_dict → from_dict should preserve all fields."""
        e = self._make_event(id=99)
        d = e.to_dict()
        e2 = Event.from_dict(d)
        assert e.to_dict() == e2.to_dict()

    def test_roundtrip_json(self):
        """to_json → from_json should preserve all fields."""
        e = self._make_event(id=55)
        raw = e.to_json()
        e2 = Event.from_json(raw)
        assert e.to_dict() == e2.to_dict()

    def test_details_defaults_to_empty_dict(self):
        e = Event(
            source_ip="10.0.0.1",
            event_type=EventType.UNKNOWN,
            severity=Severity.LOW,
        )
        assert e.details == {}

    def test_port_scan_event(self):
        e = self._make_event(
            event_type=EventType.PORT_SCAN,
            severity=Severity.MEDIUM,
            details={"ports": [22, 80, 443, 3306, 8080], "total_unique": 5},
        )
        assert e.event_type == EventType.PORT_SCAN
        assert len(e.details["ports"]) == 5

    def test_web_enum_event(self):
        e = self._make_event(
            event_type=EventType.WEB_ENUMERATION,
            severity=Severity.MEDIUM,
            details={"paths": ["/admin", "/wp-login.php", "/.env"], "status_404": 10},
        )
        d = e.to_dict()
        restored = Event.from_dict(d)
        assert restored.details["paths"] == ["/admin", "/wp-login.php", "/.env"]


# ---------------------------------------------------------------------------
# IPInfo Tests
# ---------------------------------------------------------------------------

class TestIPInfo:
    def test_creation(self):
        ip = IPInfo(ip="192.168.56.10")
        assert ip.ip == "192.168.56.10"
        assert ip.event_count == 0
        assert ip.risk_score == 0.0

    def test_roundtrip(self):
        ip = IPInfo(ip="10.0.0.5", event_count=15, risk_score=75.5)
        d = ip.to_dict()
        restored = IPInfo.from_dict(d)
        assert restored.ip == "10.0.0.5"
        assert restored.event_count == 15
        assert restored.risk_score == 75.5


# ---------------------------------------------------------------------------
# Ban Tests
# ---------------------------------------------------------------------------

class TestBan:
    def test_creation(self):
        b = Ban(ip="192.168.56.10", reason="SSH brute force detected")
        assert b.ip == "192.168.56.10"
        assert b.status == BanStatus.ACTIVE
        assert b.expires_at == ""

    def test_roundtrip(self):
        b = Ban(ip="10.0.0.1", reason="port scan", expires_at="2026-12-31T00:00:00Z")
        d = b.to_dict()
        restored = Ban.from_dict(d)
        assert restored.ip == "10.0.0.1"
        assert restored.status == BanStatus.ACTIVE
        assert restored.expires_at == "2026-12-31T00:00:00Z"


# ---------------------------------------------------------------------------
# ThreatIntel Tests
# ---------------------------------------------------------------------------

class TestThreatIntel:
    def test_creation(self):
        ti = ThreatIntel(ip="185.220.101.1")
        assert ti.ip == "185.220.101.1"
        assert ti.abuse_confidence_score == 0.0
        assert ti.lookup_result == {}

    def test_roundtrip_with_raw_response(self):
        raw_api = {
            "data": {
                "abuseConfidenceScore": 85,
                "countryCode": "DE",
                "isp": "Tor Exit Node",
            }
        }
        ti = ThreatIntel(
            ip="185.220.101.1",
            abuse_confidence_score=85.0,
            country="DE",
            isp="Tor Exit Node",
            usage_type="Data Center/Web Hosting",
            lookup_result=raw_api,
        )
        d = ti.to_dict()
        restored = ThreatIntel.from_dict(d)
        assert restored.abuse_confidence_score == 85.0
        assert restored.country == "DE"
        assert restored.lookup_result["data"]["abuseConfidenceScore"] == 85


# ---------------------------------------------------------------------------
# Alert Tests
# ---------------------------------------------------------------------------

class TestAlert:
    def test_creation(self):
        a = Alert(event_id=1, channel=AlertChannel.TELEGRAM)
        assert a.event_id == 1
        assert a.channel == AlertChannel.TELEGRAM
        assert a.status == AlertStatus.PENDING

    def test_roundtrip(self):
        a = Alert(
            event_id=42,
            channel=AlertChannel.EMAIL,
            status=AlertStatus.SENT,
            sent_at="2026-05-15T10:00:00Z",
        )
        d = a.to_dict()
        restored = Alert.from_dict(d)
        assert restored.event_id == 42
        assert restored.channel == AlertChannel.EMAIL
        assert restored.status == AlertStatus.SENT


# ---------------------------------------------------------------------------
# Helper Tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_utcnow_format(self):
        ts = _utcnow()
        # Should be parseable as ISO format
        from datetime import datetime, timezone
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None
