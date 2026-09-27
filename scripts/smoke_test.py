"""
Standalone smoke test for the SecureNet Lab detection core.

Runs without pytest, using only the standard library plus the project's
dependency-free modules. Simulates three attacks (SSH brute force, web
enumeration, SQL injection) and asserts the detector reacts. Exits
non-zero on any failure so it can gate a commit.
"""

import sys
import os
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collector.collector import parse_apache_line, parse_sshd_line, LogRecord
from src.detector.detector import Detector
from src.models import EventType, Severity
from src.storage import Database

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name}  {detail}")
        failures.append(name)


print("\n[1] parsing real log lines")
ssh_line = ("Oct 11 22:14:15 srv sshd[1234]: Failed password for root "
            "from 192.168.56.10 port 51234 ssh2")
rec = parse_sshd_line(ssh_line)
check("sshd line parses", rec is not None)
check("sshd ip extracted", rec and rec.source_ip == "192.168.56.10", rec and rec.source_ip)
check("sshd action failed", rec and rec.action == "failed")

ap_line = ('192.168.56.10 - - [10/Oct/2026:13:55:36 -0700] '
           '"GET /admin?id=1%27+UNION+SELECT+1 -- HTTP/1.1" 404 153 "-" "sqlmap/1.7"')
arec = parse_apache_line(ap_line)
check("apache line parses", arec is not None)
check("apache status 404", arec and arec.status == 404, arec and arec.status)
check("apache ua sqlmap", arec and "sqlmap" in arec.user_agent)

print("\n[2] detector reacts to SSH brute force")
det = Detector(brute_force_threshold=3, window=300, alert_cooldown=0)
found = []
for i in range(6):
    found += det.process(LogRecord(
        kind="sshd", source_ip="10.0.0.9", user="root", action="failed",
        timestamp=datetime(2026, 10, 11, 10, 0, 0) + timedelta(seconds=i)))
brute = [e for e in found if e.event_type == EventType.SSH_BRUTE_FORCE]
check("brute force event raised", len(brute) >= 1, f"got {len(brute)}")
check("attempts counted", brute and brute[0].details["attempts"] >= 3,
      brute and brute[0].details.get("attempts"))
check("mitre technique T1110", brute and brute[0].mitre_technique == "T1110")

print("\n[3] detector reacts to web scanning")
det2 = Detector(web_enum_threshold=4, window=300, alert_cooldown=0)
found2 = []
for i, p in enumerate(["/a", "/b", "/c", "/d", "/e"]):
    found2 += det2.process(LogRecord(
        kind="apache", source_ip="10.0.0.9", path=p, status=404,
        user_agent="gobuster/3.6",
        timestamp=datetime(2026, 10, 11, 10, 0, 0) + timedelta(seconds=i)))
types = {e.event_type for e in found2}
check("web enumeration raised", EventType.WEB_ENUMERATION in types, types)
check("suspicious agent raised", EventType.SUSPICIOUS_USER_AGENT in types, types)

print("\n[4] SQLi and traversal signatures")
det3 = Detector(window=300, alert_cooldown=0)
sqli = det3.process(LogRecord(kind="apache", source_ip="1.1.1.1",
                              path="/x?id=1' OR '1'='1", status=500,
                              timestamp=datetime(2026, 10, 11, 10, 0, 0)))
check("sqli detected", any(e.event_type == EventType.SQL_INJECTION for e in sqli))
trav = det3.process(LogRecord(kind="apache", source_ip="1.1.1.1",
                              path="/../../etc/passwd", status=400,
                              timestamp=datetime(2026, 10, 11, 10, 0, 1)))
check("traversal detected",
      any(e.event_type == EventType.DIRECTORY_TRAVERSAL for e in trav))

print("\n[5] normal traffic stays quiet")
det4 = Detector(window=300, alert_cooldown=0)
noise = []
for p in ["/", "/about", "/style.css", "/logo.png"]:
    noise += det4.process(LogRecord(kind="apache", source_ip="8.8.8.8", path=p,
                                    status=200, user_agent="Mozilla/5.0",
                                    timestamp=datetime(2026, 10, 11, 10, 0, 0)))
check("benign traffic produces no events", noise == [], noise)

print("\n[6] storage round-trip on a real database file")
with tempfile.TemporaryDirectory() as td:
    db = Database(os.path.join(td, "smoke.db"))
    from src.models import Event, Ban
    eid = db.insert_event(Event(source_ip="1.2.3.4",
                                event_type=EventType.SSH_BRUTE_FORCE,
                                severity=Severity.HIGH,
                                details={"attempts": 9}))
    db.insert_ban(Ban(ip="1.2.3.4", reason="smoke"))
    stored = db.recent_events(5)
    check("event persisted", len(stored) == 1)
    check("details preserved", stored[0].details == {"attempts": 9})
    check("ban persisted", len(db.active_bans()) == 1)
    summary = db.summary()
    check("summary totals", summary["total_events"] == 1 and summary["active_bans"] == 1)
    check("top attackers", db.top_attackers()[0]["count"] == 1)
    db.close()

print("\n[7] orchestrator wiring (SSH, firewall, alerts injected as fakes)")
from unittest.mock import MagicMock
from src.orchestrator.main import Pipeline

with tempfile.TemporaryDirectory() as td:
    db = Database(os.path.join(td, "pipe.db"))

    collector = MagicMock()
    collector.poll.return_value = [
        LogRecord(kind="sshd", source_ip="10.0.0.9", user="root", action="failed",
                  timestamp=datetime(2026, 10, 11, 10, 0, 0) + timedelta(seconds=i),
                  raw=f"Failed password for root from 10.0.0.9 (try {i})")
        for i in range(5)
    ]
    banner = MagicMock()
    banner.ban.return_value = True
    banner.expire_old_bans.return_value = 0
    alerter = MagicMock()
    alerter.send.return_value = []
    intel = MagicMock()
    intel.check.return_value = None
    intel.is_malicious.return_value = False

    pipe = Pipeline(
        db=db, collector=collector,
        detector=Detector(brute_force_threshold=3, window=300, alert_cooldown=0),
        intel=intel, banner=banner, alerter=alerter, interval=1,
    )
    stats = pipe.run_once()
    check("pipeline collected records", stats["collected"] == 5, stats)
    check("pipeline raised events", stats["events"] >= 1, stats)
    check("pipeline applied ban", stats["bans"] >= 1, stats)
    check("pipeline persisted event", len(db.recent_events(10)) >= 1)
    info = db.get_ip_info("10.0.0.9")
    check("risk score tracked", info is not None and info.risk_score >= 40,
          info and info.risk_score)
    db.close()

print("\n[8] alert message formatting (no network)")
from src.alerts.alerts import AlertManager
from src.models import Event, ThreatIntel
with tempfile.TemporaryDirectory() as td:
    db = Database(os.path.join(td, "alerts.db"))
    mgr = AlertManager(db, telegram_token="tok", telegram_chat_id="1", cooldown=0)
    ev = Event(source_ip="1.2.3.4", event_type=EventType.SSH_BRUTE_FORCE,
               severity=Severity.HIGH, mitre_technique="T1110",
               details={"attempts": 12}, id=1)
    ti = ThreatIntel(ip="1.2.3.4", abuse_confidence_score=88.0,
                     country="RU", isp="Evil Hosting")
    msg = mgr.format_message(ev, ti)
    check("message has ip", "1.2.3.4" in msg)
    check("message has mitre", "T1110" in msg)
    check("message has intel score", "88" in msg)
    db.close()

print("\n[9] threat intel caching without network")
from unittest.mock import patch
from src.threat_intel.threat_intel import ThreatIntelClient
with tempfile.TemporaryDirectory() as td:
    db = Database(os.path.join(td, "ti.db"))
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": {"abuseConfidenceScore": 91,
                                       "countryCode": "CN", "isp": "Bad ISP",
                                       "usageType": "Hosting"}}
    with patch("src.threat_intel.threat_intel.requests.get", return_value=resp) as mg:
        client = ThreatIntelClient(db, api_key="k", cache_ttl=3600, min_score=50)
        first = client.check("5.5.5.5")
        second = client.check("5.5.5.5")
        check("intel fetched", first and first.abuse_confidence_score == 91)
        check("intel cached (1 call)", mg.call_count == 1, f"calls={mg.call_count}")
        check("is_malicious true", client.is_malicious("5.5.5.5") is True)
    db.close()

# a client with no key and an empty cache must return None, not raise
with tempfile.TemporaryDirectory() as td:
    fresh_db = Database(os.path.join(td, "ti2.db"))
    client2 = ThreatIntelClient(fresh_db, api_key="", min_score=50)
    check("disabled without key", client2.enabled is False)
    check("disabled check returns None", client2.check("5.5.5.5") is None)
    fresh_db.close()

print("\n" + "=" * 60)
if failures:
    print(f"SMOKE TEST FAILED: {len(failures)} check(s) -> {failures}")
    sys.exit(1)
print("ALL SMOKE CHECKS PASSED")