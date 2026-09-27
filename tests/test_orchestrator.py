"""
Tests for the pipeline orchestrator.

Everything downstream of the collector is a fake, so these tests check
the wiring and the decision logic: which events get stored, which get
banned, and that one bad event does not take the cycle down.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from src.collector.collector import LogRecord
from src.detector.detector import Detector
from src.models import Event, EventType, Severity
from src.orchestrator.main import Pipeline
from src.storage import Database


@pytest.fixture
def db(tmp_path) -> Database:
    database = Database(tmp_path / "pipe.db")
    yield database
    database.close()


def ssh_fail(ip: str, offset: int = 0) -> LogRecord:
    return LogRecord(
        kind="sshd", source_ip=ip, user="root", action="failed",
        timestamp=datetime(2026, 10, 11, 10, 0, 0) + timedelta(seconds=offset),
        raw=f"Failed password for root from {ip}",
    )


def build_pipeline(db, records, ban_result=True) -> Pipeline:
    collector = MagicMock()
    collector.poll.return_value = records

    banner = MagicMock()
    banner.ban.return_value = ban_result
    banner.expire_old_bans.return_value = 0

    alerter = MagicMock()
    alerter.send.return_value = []

    intel = MagicMock()
    intel.check.return_value = None
    intel.is_malicious.return_value = False

    return Pipeline(
        db=db,
        collector=collector,
        detector=Detector(brute_force_threshold=3, window=300, alert_cooldown=0),
        intel=intel,
        banner=banner,
        alerter=alerter,
        interval=1,
    )


def test_run_once_stores_events(db):
    pipeline = build_pipeline(db, [ssh_fail("1.2.3.4", i) for i in range(5)])
    stats = pipeline.run_once()
    assert stats["collected"] == 5
    assert stats["events"] >= 1
    assert len(db.recent_events(10)) >= 1


def test_high_severity_triggers_ban(db):
    pipeline = build_pipeline(db, [ssh_fail("1.2.3.4", i) for i in range(5)])
    stats = pipeline.run_once()
    assert stats["bans"] >= 1
    pipeline.banner.ban.assert_called()


def test_low_volume_does_not_ban(db):
    pipeline = build_pipeline(db, [ssh_fail("1.2.3.4", 0)])
    stats = pipeline.run_once()
    assert stats["events"] == 0
    pipeline.banner.ban.assert_not_called()


def test_threat_intel_alone_can_trigger_ban(db):
    pipeline = build_pipeline(db, [ssh_fail("1.2.3.4", 0)])
    pipeline.intel.is_malicious.return_value = True
    pipeline.intel.check.return_value = None
    # craft an event directly through the handler path
    event = Event(
        source_ip="9.9.9.9",
        event_type=EventType.SERVICE_PROBE,
        severity=Severity.LOW,
    )
    stats = {"collected": 0, "events": 0, "bans": 0, "alerts": 0}
    pipeline._handle_event(event, stats)
    pipeline.banner.ban.assert_called_with("9.9.9.9", "service_probe (low)")


def test_event_is_recorded_even_when_handling_partially_fails(db):
    pipeline = build_pipeline(db, [ssh_fail("1.2.3.4", i) for i in range(5)])
    # alerter explodes, but the event must still be stored
    pipeline.alerter.send.side_effect = RuntimeError("telegram down")
    pipeline.run_once()
    assert len(db.recent_events(10)) >= 1


def test_ip_risk_score_tracked(db):
    pipeline = build_pipeline(db, [ssh_fail("1.2.3.4", i) for i in range(5)])
    pipeline.run_once()
    info = db.get_ip_info("1.2.3.4")
    assert info is not None
    assert info.event_count >= 1
    assert info.risk_score >= 40


def test_expired_bans_swept_each_cycle(db):
    pipeline = build_pipeline(db, [])
    pipeline.banner.expire_old_bans.return_value = 2
    stats = pipeline.run_once()
    assert stats["bans"] == 2


def test_no_records_is_a_clean_cycle(db):
    pipeline = build_pipeline(db, [])
    stats = pipeline.run_once()
    assert stats == {"collected": 0, "events": 0, "bans": 0, "alerts": 0}

def test_failed_cycle_does_not_stop_the_loop(db, monkeypatch):
    pipeline = build_pipeline(db, [])
    calls = []

    def flaky_run_once():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")
        pipeline._stop = True
        return {"collected": 0, "events": 0, "bans": 0, "alerts": 0}

    pipeline.run_once = flaky_run_once
    monkeypatch.setattr("src.orchestrator.main.time.sleep", lambda s: None)
    pipeline.run()
    assert len(calls) == 2
