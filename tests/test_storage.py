"""
Tests for the SQLite storage layer.

Each test gets a fresh database in a tmp_path, so nothing leaks between
tests and the real data/securenet.db is never touched.
"""

import pytest

from src.models import (
    Alert,
    AlertChannel,
    AlertStatus,
    Ban,
    BanStatus,
    Event,
    EventType,
    Severity,
    ThreatIntel,
)
from src.storage import Database


@pytest.fixture
def db(tmp_path) -> Database:
    database = Database(tmp_path / "test.db")
    yield database
    database.close()


def make_event(ip: str = "1.2.3.4", **kwargs) -> Event:
    defaults = dict(
        source_ip=ip,
        event_type=EventType.SSH_BRUTE_FORCE,
        severity=Severity.HIGH,
        raw_log="Failed password for root",
        mitre_technique="T1110",
        details={"attempts": 5},
    )
    defaults.update(kwargs)
    return Event(**defaults)


class TestEvents:
    def test_insert_assigns_id(self, db):
        event = make_event()
        assert db.insert_event(event) > 0
        assert event.id is not None

    def test_round_trip_preserves_details(self, db):
        db.insert_event(make_event(details={"attempts": 12, "users": ["root"]}))
        stored = db.recent_events(1)[0]
        assert stored.details == {"attempts": 12, "users": ["root"]}
        assert stored.event_type == EventType.SSH_BRUTE_FORCE
        assert stored.severity == Severity.HIGH

    def test_recent_events_ordered_newest_first(self, db):
        for i in range(3):
            db.insert_event(make_event(ip=f"10.0.0.{i}"))
        ips = [e.source_ip for e in db.recent_events(10)]
        assert ips == ["10.0.0.2", "10.0.0.1", "10.0.0.0"]

    def test_events_by_ip_filters(self, db):
        db.insert_event(make_event(ip="1.1.1.1"))
        db.insert_event(make_event(ip="2.2.2.2"))
        db.insert_event(make_event(ip="1.1.1.1"))
        assert len(db.events_by_ip("1.1.1.1")) == 2

    def test_counts_by_type_and_severity(self, db):
        db.insert_event(make_event())
        db.insert_event(make_event(event_type=EventType.PORT_SCAN,
                                   severity=Severity.CRITICAL))
        assert db.count_events_by_type()["ssh_brute_force"] == 1
        assert db.count_events_by_severity()["critical"] == 1

    def test_top_attackers(self, db):
        for _ in range(3):
            db.insert_event(make_event(ip="1.1.1.1"))
        db.insert_event(make_event(ip="2.2.2.2"))
        top = db.top_attackers(5)
        assert top[0]["ip"] == "1.1.1.1"
        assert top[0]["count"] == 3


class TestBans:
    def test_active_bans_only(self, db):
        b1 = Ban(ip="1.1.1.1", reason="brute force")
        db.insert_ban(b1)
        b2 = Ban(ip="2.2.2.2", reason="scan")
        db.insert_ban(b2)
        db.set_ban_status(b2.id, BanStatus.EXPIRED)
        active = db.active_bans()
        assert len(active) == 1
        assert active[0].ip == "1.1.1.1"

    def test_get_active_ban(self, db):
        db.insert_ban(Ban(ip="1.1.1.1"))
        assert db.get_active_ban("1.1.1.1") is not None
        assert db.get_active_ban("9.9.9.9") is None

    def test_ban_status_round_trip(self, db):
        ban = Ban(ip="1.1.1.1", expires_at="2026-10-11T12:00:00+00:00")
        db.insert_ban(ban)
        stored = db.get_active_ban("1.1.1.1")
        assert stored.expires_at == "2026-10-11T12:00:00+00:00"
        assert stored.status == BanStatus.ACTIVE


class TestAlerts:
    def test_alert_recorded_with_status(self, db):
        alert = Alert(event_id=1, channel=AlertChannel.TELEGRAM,
                      status=AlertStatus.SENT, sent_at="2026-10-11T10:00:00")
        db.insert_alert(alert)
        stored = db.recent_alerts(1)[0]
        assert stored.channel == AlertChannel.TELEGRAM
        assert stored.status == AlertStatus.SENT


class TestThreatIntel:
    def test_upsert_inserts_then_updates(self, db):
        db.upsert_threat_intel(ThreatIntel(ip="1.1.1.1",
                                           abuse_confidence_score=90))
        db.upsert_threat_intel(ThreatIntel(ip="1.1.1.1",
                                           abuse_confidence_score=20))
        stored = db.get_threat_intel("1.1.1.1")
        assert stored.abuse_confidence_score == 20

    def test_missing_returns_none(self, db):
        assert db.get_threat_intel("8.8.8.8") is None


class TestIpInfo:
    def test_touch_creates_then_increments(self, db):
        db.touch_ip("1.1.1.1", "2026-10-11T10:00:00", risk_score=70)
        db.touch_ip("1.1.1.1", "2026-10-11T10:05:00", risk_score=90)
        info = db.get_ip_info("1.1.1.1")
        assert info.event_count == 2
        assert info.risk_score == 90
        assert info.first_seen == "2026-10-11T10:00:00"
        assert info.last_seen == "2026-10-11T10:05:00"


class TestSummary:
    def test_summary_shape(self, db):
        db.insert_event(make_event())
        db.insert_ban(Ban(ip="1.1.1.1"))
        summary = db.summary()
        assert summary["total_events"] == 1
        assert summary["active_bans"] == 1
        assert summary["unique_attackers"] == 1
        assert "events_by_severity" in summary