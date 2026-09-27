"""
Tests for the sliding-window detector.

These use small thresholds and synthetic LogRecords so each rule can be
exercised in isolation without any network or SSH dependency.
"""

from datetime import datetime, timedelta

import pytest

from src.collector.collector import LogRecord
from src.detector.detector import Detector
from src.models import EventType, Severity


def ssh_fail(ip: str, user: str = "root", offset_s: int = 0) -> LogRecord:
    return LogRecord(
        kind="sshd",
        source_ip=ip,
        timestamp=datetime(2026, 10, 11, 10, 0, 0) + timedelta(seconds=offset_s),
        user=user,
        action="failed",
        raw=f"Failed password for {user} from {ip}",
    )


def web(ip: str, path: str, status: int = 200, ua: str = "Mozilla/5.0",
        offset_s: int = 0) -> LogRecord:
    return LogRecord(
        kind="apache",
        source_ip=ip,
        timestamp=datetime(2026, 10, 11, 10, 0, 0) + timedelta(seconds=offset_s),
        method="GET",
        path=path,
        status=status,
        user_agent=ua,
        raw=f'GET {path} HTTP/1.1" {status}',
    )


@pytest.fixture
def detector() -> Detector:
    return Detector(
        brute_force_threshold=3,
        web_enum_threshold=4,
        window=300,
        alert_cooldown=0,
    )


class TestBruteForce:
    def test_fires_at_threshold(self, detector):
        events = []
        for i in range(3):
            events += detector.process(ssh_fail("1.2.3.4", offset_s=i))
        assert any(e.event_type == EventType.SSH_BRUTE_FORCE for e in events)

    def test_below_threshold_is_quiet(self, detector):
        events = []
        for i in range(2):
            events += detector.process(ssh_fail("1.2.3.4", offset_s=i))
        assert events == []

    def test_counts_attempts_and_users(self, detector):
        for i, user in enumerate(["root", "admin", "oracle"]):
            detector.process(ssh_fail("1.2.3.4", user, offset_s=i))
        events = detector.process(ssh_fail("1.2.3.4", "www", offset_s=3))
        brute = [e for e in events if e.event_type == EventType.SSH_BRUTE_FORCE]
        assert len(brute) == 1
        assert brute[0].details["attempts"] == 4
        assert set(brute[0].details["users_tried"]) >= {"root", "admin", "oracle"}

    def test_escalates_to_critical_on_volume(self, detector):
        events = []
        for i in range(13):
            events += detector.process(ssh_fail("1.2.3.4", offset_s=i))
        brute = [e for e in events if e.event_type == EventType.SSH_BRUTE_FORCE]
        assert brute[-1].severity == Severity.CRITICAL

    def test_old_attempts_fall_out_of_window(self, detector):
        detector.process(ssh_fail("1.2.3.4", offset_s=0))
        detector.process(ssh_fail("1.2.3.4", offset_s=1))
        # third attempt arrives well past the 300s window: only 1 in window
        events = detector.process(ssh_fail("1.2.3.4", offset_s=900))
        assert events == []

    def test_separate_ips_tracked_independently(self, detector):
        for i in range(3):
            detector.process(ssh_fail("1.1.1.1", offset_s=i))
        events = detector.process(ssh_fail("2.2.2.2", offset_s=0))
        assert events == []


class TestWebAttacks:
    def test_sql_injection_detected(self, detector):
        events = detector.process(web("5.5.5.5", "/p?id=1 UNION SELECT password"))
        assert any(e.event_type == EventType.SQL_INJECTION for e in events)
        assert events[0].mitre_technique == "T1190"

    def test_directory_traversal_detected(self, detector):
        events = detector.process(web("5.5.5.5", "/../../etc/passwd"))
        types = {e.event_type for e in events}
        assert EventType.DIRECTORY_TRAVERSAL in types

    def test_scanner_user_agent_detected(self, detector):
        events = detector.process(
            web("5.5.5.5", "/", ua="gobuster/3.6")
        )
        assert any(e.event_type == EventType.SUSPICIOUS_USER_AGENT for e in events)

    def test_sensitive_path_is_flagged(self, detector):
        events = detector.process(web("5.5.5.5", "/.env"))
        assert any(e.event_type == EventType.WEB_ENUMERATION for e in events)

    def test_many_404s_trigger_enumeration(self, detector):
        events = []
        for i, path in enumerate(["/a", "/b", "/c", "/d", "/e"]):
            events += detector.process(web("5.5.5.5", path, status=404, offset_s=i))
        enum = [e for e in events if e.event_type == EventType.WEB_ENUMERATION]
        assert enum
        assert enum[0].details["404_count"] >= 4

    def test_normal_traffic_is_quiet(self, detector):
        for path in ["/", "/about", "/style.css", "/logo.png"]:
            events = detector.process(web("9.9.9.9", path, status=200))
            assert events == []


class TestPortScan:
    def test_fires_after_n_ports(self):
        det = Detector(window=300, alert_cooldown=0)
        from src.config import settings
        threshold = settings.port_scan_threshold
        event = None
        for port in range(1, threshold + 2):
            event = det.record_port_probe("7.7.7.7", port)
        assert event is not None
        assert event.event_type == EventType.PORT_SCAN
        assert event.mitre_technique == "T1046"

    def test_below_threshold_quiet(self):
        det = Detector(window=300, alert_cooldown=0)
        assert det.record_port_probe("7.7.7.7", 22) is None


class TestAlertCooldown:
    def test_sustained_attack_alerts_once_per_cooldown(self):
        det = Detector(
            brute_force_threshold=3, window=300, alert_cooldown=1000
        )
        events = []
        for i in range(20):
            events += det.process(ssh_fail("1.2.3.4", offset_s=i))
        brute = [e for e in events if e.event_type == EventType.SSH_BRUTE_FORCE]
        assert len(brute) == 1


def ids(ip: str, sid: int = 0, dest_port: int = 80, action: str = "alert",
        severity: int = 1, dest_ip: str = "192.168.56.20", mitre: str = "",
        offset_s: int = 0) -> LogRecord:
    return LogRecord(
        kind="suricata",
        source_ip=ip,
        timestamp=datetime(2026, 10, 11, 10, 0, 0) + timedelta(seconds=offset_s),
        action=action,
        dest_ip=dest_ip,
        dest_port=dest_port,
        signature=f"sid {sid}",
        signature_id=sid,
        ids_severity=severity,
        mitre_technique=mitre,
        raw="{}",
    )


class TestSuricata:
    TARGET = "192.168.56.20"

    def make(self, cooldown: int = 0) -> Detector:
        return Detector(window=300, alert_cooldown=cooldown,
                        protected_ips={self.TARGET})

    def test_custom_sid_maps_to_pipeline_event_type(self):
        events = self.make().process(ids("6.6.6.6", sid=9000010, mitre="T1190"))
        assert len(events) == 1
        e = events[0]
        assert e.event_type == EventType.SQL_INJECTION
        assert e.severity == Severity.HIGH
        assert e.mitre_technique == "T1190"
        assert e.details["source"] == "suricata"
        assert e.details["direction"] == "inbound"

    def test_unknown_sid_is_generic_ids_alert(self):
        events = self.make().process(ids("6.6.6.6", sid=2010935, severity=2))
        assert events[0].event_type == EventType.IDS_ALERT
        assert events[0].severity == Severity.MEDIUM

    def test_generic_alerts_cooldown_is_per_signature(self):
        det = self.make(cooldown=1000)
        a = det.process(ids("6.6.6.6", sid=2000001, offset_s=0))
        b = det.process(ids("6.6.6.6", sid=2000002, offset_s=1))
        c = det.process(ids("6.6.6.6", sid=2000001, offset_s=2))
        assert len(a) == 1 and len(b) == 1   # different rules both alert
        assert c == []                        # same rule is rate-limited

    def test_ids_and_log_detection_share_cooldown(self):
        det = Detector(brute_force_threshold=1, window=300, alert_cooldown=1000,
                       protected_ips={self.TARGET})
        assert det.process(ids("6.6.6.6", sid=9000001, dest_port=22))
        # the same brute force seen in the sshd log is not a second alert
        assert det.process(ssh_fail("6.6.6.6", offset_s=1)) == []

    def test_reverse_shell_blames_remote_end(self):
        rec = ids(self.TARGET, sid=9000050, dest_ip="203.0.113.5", dest_port=4444)
        events = self.make().process(rec)
        assert len(events) == 1
        e = events[0]
        assert e.source_ip == "203.0.113.5"      # never our own server
        assert e.severity == Severity.CRITICAL
        assert e.details["direction"] == "outbound"

    def test_flows_to_many_ports_are_a_port_scan(self):
        from src.config import settings
        det = self.make()
        events = []
        for port in range(1, settings.port_scan_threshold + 1):
            events += det.process(ids("7.7.7.7", action="flow", dest_port=port))
        scans = [e for e in events if e.event_type == EventType.PORT_SCAN]
        assert scans and scans[0].mitre_technique == "T1046"

    def test_protected_host_outbound_flows_are_not_a_scan(self):
        from src.config import settings
        det = self.make()
        events = []
        for port in range(1, settings.port_scan_threshold + 5):
            events += det.process(ids(self.TARGET, action="flow", dest_port=port,
                                      dest_ip="1.1.1.1"))
        assert events == []

    def test_single_flow_is_quiet(self):
        assert self.make().process(ids("7.7.7.7", action="flow", dest_port=22)) == []
