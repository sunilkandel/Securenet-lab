"""
Attack detector for SecureNet Lab.

Turns parsed LogRecords into Events. The detector is a stateful sliding-
window counter: for each source IP it remembers what happened in the
last `detection_window` seconds, and raises an Event when a threshold is
crossed.

Design notes:

- Stateless parsers, stateful detector. All the memory lives in this
  class, which makes it easy to reason about and to test.
- Per-(IP, type) re-alert suppression. If someone brute-forces SSH for
  an hour, you get one alert per cooldown window, not one per attempt.
- Pure-Python and dependency-free, so unit tests run in milliseconds.
- No I/O. The orchestrator decides what to do with Events.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from src.collector.collector import LogRecord
from src.config import settings
from src.logging_setup import get_logger
from src.models import Event, EventType, Severity

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Web attack signatures
# ---------------------------------------------------------------------------

# These are intentionally simple substring/regex checks. The goal is to
# catch the noisy, common stuff from scanners and scripts, not to be a WAF.

_SQLI_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in [
        r"union\s+select",
        r"union\s+all\s+select",
        r"'\s*or\s+'1'='1",
        r"'\s*or\s+1=1",
        r";\s*drop\s+table",
        r"select.+from.+information_schema",
        r"sleep\s*\(\s*\d+\s*\)",
        r"benchmark\s*\(",
        r"load_file\s*\(",
    ]
]

_TRAVERSAL_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"/etc/passwd",
        r"/etc/shadow",
        r"boot\.ini",
        r"win\.ini",
    ]
]

_BAD_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "hydra", "nuclei",
    "gobuster", "dirbuster", "wfuzz", "acunetix", "nessus",
    "openvas", "wpscan", "zgrab",
]

# Paths that scanners hammer but real users never request. A request for
# one of these is suspicious on its own, regardless of volume.
_SENSITIVE_PATHS = [
    "/.env", "/.git", "/wp-admin", "/wp-login", "/xmlrpc.php",
    "/phpmyadmin", "/.aws/credentials", "/config.php", "/admin/config",
    "/server-status", "/actuator", "/.ssh",
]


# Our custom Suricata signature IDs (suricata/rules/custom.rules) mapped
# onto the pipeline's event types, so a network-side and a log-side hit
# for the same attack land in the same bucket and share one cooldown.
# Anything unlisted (Emerging Threats rules, Shellshock, reverse shell)
# becomes a generic IDS_ALERT.
_SID_EVENT_TYPES: dict[int, EventType] = {
    9000001: EventType.SSH_BRUTE_FORCE,
    9000002: EventType.PORT_SCAN,
    9000003: EventType.PORT_SCAN,
    9000004: EventType.PORT_SCAN,
    9000010: EventType.SQL_INJECTION,
    9000011: EventType.SQL_INJECTION,
    9000012: EventType.DIRECTORY_TRAVERSAL,
    9000013: EventType.DIRECTORY_TRAVERSAL,
    9000014: EventType.DIRECTORY_TRAVERSAL,
    9000020: EventType.SUSPICIOUS_USER_AGENT,
    9000021: EventType.SUSPICIOUS_USER_AGENT,
    9000022: EventType.SUSPICIOUS_USER_AGENT,
    9000023: EventType.SUSPICIOUS_USER_AGENT,
    9000030: EventType.WEB_ENUMERATION,
    9000031: EventType.WEB_ENUMERATION,
    9000032: EventType.WEB_ENUMERATION,
}

# Signatures that mean "already compromised", not "being attacked".
_CRITICAL_SIDS = {9000050}  # reverse shell leaving a protected host

# Suricata severity comes from the rule's classtype priority.
_IDS_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}


@dataclass
class _IpState:
    """Per-IP sliding-window state."""
    ssh_failures: deque = field(default_factory=deque)   # timestamps
    web_404s: deque = field(default_factory=deque)       # timestamps
    sqli_hits: deque = field(default_factory=deque)
    traversal_hits: deque = field(default_factory=deque)
    ports_seen: dict[float, set] = field(default_factory=dict)  # ts -> ports
    users_tried: set = field(default_factory=set)
    paths_404: set = field(default_factory=set)
    last_alert: dict[str, float] = field(default_factory=dict)  # type -> ts


def _prune(dq: deque, window_start: float) -> None:
    """Drop timestamps older than the sliding window."""
    while dq and dq[0] < window_start:
        dq.popleft()


class Detector:
    """Sliding-window, threshold-based attack detector."""

    def __init__(
        self,
        brute_force_threshold: int | None = None,
        web_enum_threshold: int | None = None,
        window: int | None = None,
        alert_cooldown: int | None = None,
        protected_ips: set[str] | None = None,
    ) -> None:
        self.brute_force_threshold = (
            settings.brute_force_threshold
            if brute_force_threshold is None
            else brute_force_threshold
        )
        self.web_enum_threshold = (
            settings.web_enum_threshold
            if web_enum_threshold is None
            else web_enum_threshold
        )
        self.window = settings.detection_window if window is None else window
        # reuse the alert cooldown so sustained attacks don't spam
        # (explicit `is None` check: 0 is a valid "no cooldown" value and
        # `x or default` would incorrectly fall back to the default for it)
        self.alert_cooldown = (
            settings.alert_cooldown if alert_cooldown is None else alert_cooldown
        )
        # Hosts we defend. Their own outbound connections are not a port
        # scan, and alerts they originate point at the remote end.
        self.protected_ips = (
            {settings.target_ip} if protected_ips is None else set(protected_ips)
        )
        self._state: dict[str, _IpState] = defaultdict(_IpState)

    # -- public API -----------------------------------------------------------

    def process(self, record: LogRecord) -> list[Event]:
        """Feed one log record in; get zero or more Events out."""
        now = record.timestamp.timestamp() if record.timestamp else time.time()
        st = self._state[record.source_ip]
        window_start = now - self.window

        events: list[Event] = []
        if record.kind == "sshd":
            events.extend(self._process_sshd(record, st, now, window_start))
        elif record.kind == "apache":
            events.extend(self._process_apache(record, st, now, window_start))
        elif record.kind == "suricata":
            events.extend(self._process_suricata(record, now))
        return events

    def process_many(self, records: list[LogRecord]) -> list[Event]:
        out: list[Event] = []
        for rec in records:
            out.extend(self.process(rec))
        return out

    # -- sshd -----------------------------------------------------------------

    def _process_sshd(
        self, record: LogRecord, st: _IpState, now: float, window_start: float
    ) -> list[Event]:
        events: list[Event] = []

        if record.action in ("failed", "invalid_user"):
            st.ssh_failures.append(now)
            if record.user:
                st.users_tried.add(record.user)

        _prune(st.ssh_failures, window_start)

        if len(st.ssh_failures) >= self.brute_force_threshold:
            if self._can_alert(st, EventType.SSH_BRUTE_FORCE, now):
                users = sorted(st.users_tried)[:10]
                severity = (
                    Severity.CRITICAL
                    if len(st.ssh_failures) >= self.brute_force_threshold * 4
                    else Severity.HIGH
                )
                events.append(Event(
                    source_ip=record.source_ip,
                    event_type=EventType.SSH_BRUTE_FORCE,
                    severity=severity,
                    raw_log=record.raw,
                    mitre_technique="T1110",
                    details={
                        "attempts": len(st.ssh_failures),
                        "window_seconds": self.window,
                        "users_tried": users,
                    },
                ))
        return events

    # -- apache -----------------------------------------------------------------

    def _process_apache(
        self, record: LogRecord, st: _IpState, now: float, window_start: float
    ) -> list[Event]:
        events: list[Event] = []
        path = record.path or ""

        # Signature checks run on every request, no threshold needed.
        if self._matches_any(_SQLI_PATTERNS, path):
            if self._can_alert(st, EventType.SQL_INJECTION, now):
                events.append(Event(
                    source_ip=record.source_ip,
                    event_type=EventType.SQL_INJECTION,
                    severity=Severity.HIGH,
                    raw_log=record.raw,
                    mitre_technique="T1190",
                    details={"path": path, "method": record.method},
                ))

        if self._matches_any(_TRAVERSAL_PATTERNS, path):
            if self._can_alert(st, EventType.DIRECTORY_TRAVERSAL, now):
                events.append(Event(
                    source_ip=record.source_ip,
                    event_type=EventType.DIRECTORY_TRAVERSAL,
                    severity=Severity.HIGH,
                    raw_log=record.raw,
                    mitre_technique="T1083",
                    details={"path": path, "method": record.method},
                ))

        agent = (record.user_agent or "").lower()
        if any(bad in agent for bad in _BAD_AGENTS):
            if self._can_alert(st, EventType.SUSPICIOUS_USER_AGENT, now):
                events.append(Event(
                    source_ip=record.source_ip,
                    event_type=EventType.SUSPICIOUS_USER_AGENT,
                    severity=Severity.MEDIUM,
                    raw_log=record.raw,
                    mitre_technique="T1595.002",
                    details={"user_agent": record.user_agent},
                ))

        lower_path = path.lower()
        if any(lower_path.startswith(p) for p in _SENSITIVE_PATHS):
            if self._can_alert(st, EventType.WEB_ENUMERATION, now):
                events.append(Event(
                    source_ip=record.source_ip,
                    event_type=EventType.WEB_ENUMERATION,
                    severity=Severity.MEDIUM,
                    raw_log=record.raw,
                    mitre_technique="T1595.003",
                    details={"path": path, "reason": "sensitive path probe"},
                ))

        # Volume-based enumeration detection: many distinct 404s in a
        # short window is the signature of gobuster/dirb-style scanning.
        if record.status == 404:
            st.web_404s.append(now)
            if len(st.paths_404) < 500:  # cap memory per IP
                st.paths_404.add(path)
            _prune(st.web_404s, window_start)
            if len(st.web_404s) >= self.web_enum_threshold:
                if self._can_alert(st, EventType.WEB_ENUMERATION, now):
                    events.append(Event(
                        source_ip=record.source_ip,
                        event_type=EventType.WEB_ENUMERATION,
                        severity=Severity.MEDIUM,
                        raw_log=record.raw,
                        mitre_technique="T1595.003",
                        details={
                            "404_count": len(st.web_404s),
                            "window_seconds": self.window,
                            "sample_paths": sorted(st.paths_404)[:10],
                        },
                    ))
                    st.paths_404.clear()

        return events

    # -- suricata (eve.json alert / flow records) ------------------------------

    def _process_suricata(self, record: LogRecord, now: float) -> list[Event]:
        events: list[Event] = []
        outbound = record.source_ip in self.protected_ips

        # Every inbound connection counts toward port-scan detection. The
        # protected host's own outbound traffic (updates, DNS) does not.
        if record.dest_port and not outbound:
            scan = self.record_port_probe(record.source_ip, record.dest_port, when=now)
            if scan is not None:
                events.append(scan)

        if record.action != "alert":
            return events

        # Traffic leaving a protected host (e.g. a reverse shell): the host
        # to act against is the remote end, never our own server.
        offender = record.dest_ip if outbound and record.dest_ip else record.source_ip
        event_type = _SID_EVENT_TYPES.get(record.signature_id, EventType.IDS_ALERT)
        if record.signature_id in _CRITICAL_SIDS:
            severity = Severity.CRITICAL
        else:
            severity = _IDS_SEVERITY.get(record.ids_severity, Severity.MEDIUM)

        # Generic hits are rate-limited per signature, so one noisy rule
        # cannot mute a different rule for the same host.
        key = (
            f"{event_type.value}:{record.signature_id}"
            if event_type is EventType.IDS_ALERT
            else None
        )
        if not self._can_alert(self._state[offender], event_type, now, key=key):
            return events

        events.append(Event(
            source_ip=offender,
            event_type=event_type,
            severity=severity,
            raw_log=record.raw,
            mitre_technique=record.mitre_technique,
            details={
                "source": "suricata",
                "signature": record.signature,
                "signature_id": record.signature_id,
                "category": record.category,
                "dest_port": record.dest_port,
                "direction": "outbound" if outbound else "inbound",
            },
        ))
        return events

    # -- port scan (fed by Suricata or netstat-style sources) -------------------

    def record_port_probe(self, ip: str, port: int, when: float | None = None) -> Event | None:
        """Register a connection attempt to *port* from *ip*.

        Called by the Suricata EVE reader rather than the log pipeline.
        Returns a PORT_SCAN Event if the threshold was just crossed.
        """
        now = when or time.time()
        st = self._state[ip]
        window_start = now - self.window

        # keep only in-window timestamps
        st.ports_seen = {
            ts: ports for ts, ports in st.ports_seen.items() if ts >= window_start
        }
        st.ports_seen.setdefault(now, set()).add(port)

        unique_ports = set().union(*st.ports_seen.values()) if st.ports_seen else set()
        if len(unique_ports) >= settings.port_scan_threshold:
            if self._can_alert(st, EventType.PORT_SCAN, now):
                return Event(
                    source_ip=ip,
                    event_type=EventType.PORT_SCAN,
                    severity=Severity.HIGH,
                    raw_log=f"{ip} probed {len(unique_ports)} ports in {self.window}s",
                    mitre_technique="T1046",
                    details={
                        "unique_ports": len(unique_ports),
                        "window_seconds": self.window,
                        "sample_ports": sorted(unique_ports)[:20],
                    },
                )
        return None

    # -- helpers -----------------------------------------------------------------

    @staticmethod
    def _matches_any(patterns: list[re.Pattern], text: str) -> bool:
        return any(p.search(text) for p in patterns)

    def _can_alert(
        self,
        st: _IpState,
        event_type: EventType,
        now: float,
        key: str | None = None,
    ) -> bool:
        """Rate-limit alerts per (IP, type). Returns True if we should fire.

        *key* overrides the bucket (default: the event type's value).
        """
        bucket = key or event_type.value
        last = st.last_alert.get(bucket, 0.0)
        if now - last < self.alert_cooldown:
            return False
        st.last_alert[bucket] = now
        return True
