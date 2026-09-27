"""
SSH log collector for SecureNet Lab.

Pulls Apache access logs and sshd logs from the target VM over SSH and
hands the raw lines to the detector. Runs forever, tolerates the target
being rebooted or the network dropping, and survives log rotation.

Two layers, kept apart on purpose:

- Parsing (parse_apache_line / parse_sshd_line) is pure and testable.
  Give it a string, get a LogRecord or None.
- Transport (SSHLogCollector) manages the SSH connection, byte offsets,
  and reconnect backoff. It never interprets log content.

A note on offsets: we track how many bytes of each remote file we have
already read and start the next read there. If the file shrinks (log
rotation), we assume it was replaced and read the new file from the top.
Given a Database, offsets are saved after every read and restored on
start, so a restart resumes where it stopped instead of replaying the
whole log (duplicate events, alerts and bans).
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Callable, Iterator

from src.config import settings
from src.logging_setup import get_logger

if TYPE_CHECKING:
    from src.storage import Database

log = get_logger(__name__)

try:
    import paramiko
except ImportError:  # paramiko is optional for offline tests
    paramiko = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Parsed record — the collector's output contract with the detector
# ---------------------------------------------------------------------------

@dataclass
class LogRecord:
    """One parsed log line, normalized enough for detection.

    `kind` is "apache", "sshd" or "suricata". Fields not relevant to the
    source are left at their defaults.
    """
    kind: str
    source_ip: str
    timestamp: datetime | None = None
    # apache
    method: str = ""
    path: str = ""
    status: int = 0
    user_agent: str = ""
    # sshd
    user: str = ""
    action: str = ""          # "failed", "accepted", "invalid_user", ...
    port: int = 0             # client source port: identifies one connection
    raw: str = ""
    # suricata (eve.json); action holds the EVE type: "alert" or "flow"
    dest_ip: str = ""
    dest_port: int = 0
    signature: str = ""
    signature_id: int = 0
    category: str = ""
    ids_severity: int = 0     # Suricata: 1 = high, 2 = medium, 3 = low
    mitre_technique: str = ""


# ---------------------------------------------------------------------------
# Apache combined-log parsing
# ---------------------------------------------------------------------------

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_apache_timestamp(raw: str) -> datetime | None:
    """Parse '10/Oct/2000:13:55:36 -0700' into a tz-aware datetime.

    Without a usable offset the result is naive (read as local time).
    """
    try:
        date_part, time_part = raw.split(":", 1)
        day, mon, year = date_part.split("/")
        clock, _, zone = time_part.partition(" ")
        hh, mm, ss = clock.split(":")
        tz = None
        if re.fullmatch(r"[+-]\d{4}", zone):
            minutes = int(zone[1:3]) * 60 + int(zone[3:5])
            tz = timezone(timedelta(minutes=-minutes if zone[0] == "-" else minutes))
        return datetime(
            int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss),
            tzinfo=tz,
        )
    except (ValueError, KeyError):
        return None


def parse_apache_line(line: str) -> LogRecord | None:
    """Parse one line of Apache combined log format.

    Returns None for malformed lines instead of raising; a hostile client
    controls most of these bytes, so the parser has to be forgiving.

    Example line:
        192.168.56.10 - - [10/Oct/2000:13:55:36 -0700] \\
            "GET /admin HTTP/1.1" 404 2326 "-" "sqlmap/1.7"
    """
    try:
        ip, rest = line.split(" ", 1)
        if not _is_ip(ip):
            return None
        # skip ident/authuser fields: "- - ["
        ts_start = rest.index("[") + 1
        ts_end = rest.index("]")
        timestamp = _parse_apache_timestamp(rest[ts_start:ts_end])

        # request is the first quoted string after the timestamp
        req_start = rest.index('"', ts_end) + 1
        req_end = rest.index('"', req_start)
        request = rest[req_start:req_end]
        parts = request.split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""

        tail = rest[req_end + 1:].strip().split(" ")
        status = int(tail[0]) if tail and tail[0].isdigit() else 0

        # user agent is the last quoted string on the line
        ua = ""
        last_quote = line.rfind('"')
        if last_quote > 0:
            prev_quote = line.rfind('"', 0, last_quote)
            if prev_quote > req_end:
                ua = line[prev_quote + 1:last_quote]

        return LogRecord(
            kind="apache",
            source_ip=ip,
            timestamp=timestamp,
            method=method,
            path=path,
            status=status,
            user_agent=ua,
            raw=line.strip(),
        )
    except (ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# sshd (/var/log/secure) parsing
# ---------------------------------------------------------------------------

def _parse_syslog_timestamp(raw: str) -> datetime | None:
    """Parse 'Oct 11 22:14:15'. Syslog has no year; assume current year."""
    try:
        return datetime.strptime(
            f"{datetime.now().year} {raw}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None


def _is_ip(value: str) -> bool:
    """True if *value* is a literal IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# sshd always ends these lines with " from <ip> port <n>" (plus " ssh2" on
# auth results), after the username. Anchoring on that fixed tail is what
# stops a username like "x from $(cmd)" from being read as the address.
_SSHD_TAIL = re.compile(r" from (\S+) port (\d+)(?: ssh2)?$")


def _split_user_ip(rest: str) -> tuple[str, str, int]:
    """Split '<user> from <ip> port <n> [ssh2]' into (user, ip, port)."""
    m = _SSHD_TAIL.search(rest)
    if m:
        return rest[:m.start()], m.group(1), int(m.group(2))
    if " from " in rest:
        # e.g. "Accepted publickey ... port 22 ssh2: RSA SHA256:..." or an
        # older sshd without the port: still take the LAST " from ".
        user, _, tail = rest.rpartition(" from ")
        words = tail.split(" ")
        has_port = len(words) > 2 and words[1] == "port" and words[2].isdigit()
        return user, words[0], int(words[2]) if has_port else 0
    return rest, "", 0


def parse_sshd_line(line: str) -> LogRecord | None:
    """Parse one sshd log line.

    Handles the shapes that matter for detection:
        Oct 11 22:14:15 srv sshd[123]: Failed password for root from 1.2.3.4 port 51234 ssh2
        Oct 11 22:14:15 srv sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 51235 ssh2
        Oct 11 22:14:15 srv sshd[123]: Accepted password for sunil from 1.2.3.4 port 51236 ssh2
        Oct 11 22:14:15 srv sshd[123]: Invalid user admin from 1.2.3.4 port 51237
    """
    raw = line.strip()
    if "sshd" not in raw:
        return None

    timestamp = _parse_syslog_timestamp(raw[:15])

    # Match on the fixed start of the message ("sshd[pid]: <msg>"), never
    # on a substring anywhere in the line: the username is attacker text
    # and may contain "Accepted password for" or " from <ip>".
    _, sep, msg = raw.partition("]: ")
    if not sep:
        return None

    if msg.startswith("Failed password for invalid user "):
        action = "failed"
        user, ip, port = _split_user_ip(msg[len("Failed password for invalid user "):])
    elif msg.startswith("Failed password for "):
        action = "failed"
        user, ip, port = _split_user_ip(msg[len("Failed password for "):])
    elif msg.startswith(("Accepted password for ", "Accepted publickey for ")):
        action = "accepted"
        user, ip, port = _split_user_ip(msg.split(" for ", 1)[1])
    elif msg.startswith("Invalid user "):
        action = "invalid_user"
        user, ip, port = _split_user_ip(msg[len("Invalid user "):])
    else:
        return None  # disconnects, session open/close: noise for us

    # The IP later reaches a root firewall command on the target. Anything
    # that is not a real address is dropped here, at the front door.
    if not _is_ip(ip):
        return None

    return LogRecord(
        kind="sshd",
        source_ip=ip,
        timestamp=timestamp,
        user=user,
        action=action,
        port=port,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Suricata EVE JSON parsing
# ---------------------------------------------------------------------------

# Only these EVE record types carry detection value here: "alert" is a
# rule hit, "flow" is one connection (feeds port-scan counting). http,
# dns, tls, stats and the rest are dropped at the door.
_EVE_TYPES = {"alert", "flow"}


def _parse_eve_timestamp(raw: str) -> datetime | None:
    """Parse Suricata's '2026-10-11T06:26:40.050000+0000' (tz-aware)."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(raw, fmt)
        except (ValueError, TypeError):
            continue
    return None


def parse_eve_line(line: str) -> LogRecord | None:
    """Parse one line of Suricata eve.json (one JSON object per line).

    Returns a "suricata" LogRecord for alert and flow records and None
    for anything else. Never raises: a half-written last line from a
    read that raced Suricata's writer is normal, not an error.
    """
    try:
        data = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    kind = data.get("event_type")
    ip = data.get("src_ip")
    if kind not in _EVE_TYPES or not isinstance(ip, str) or not ip:
        return None

    try:
        dest_port = int(data.get("dest_port") or 0)
    except (ValueError, TypeError):
        dest_port = 0

    rec = LogRecord(
        kind="suricata",
        source_ip=ip,
        timestamp=_parse_eve_timestamp(data.get("timestamp", "")),
        action=kind,
        dest_ip=str(data.get("dest_ip") or ""),
        dest_port=dest_port,
        raw=line.strip(),
    )

    if kind == "alert":
        alert = data.get("alert")
        if not isinstance(alert, dict):
            return None
        try:
            rec.signature_id = int(alert.get("signature_id") or 0)
            rec.ids_severity = int(alert.get("severity") or 0)
        except (ValueError, TypeError):
            return None
        rec.signature = str(alert.get("signature") or "")
        rec.category = str(alert.get("category") or "")
        # rule "metadata: mitre_technique T1110;" -> {"mitre_technique": ["T1110"]}
        meta = alert.get("metadata")
        if isinstance(meta, dict):
            techniques = meta.get("mitre_technique")
            if isinstance(techniques, list) and techniques:
                rec.mitre_technique = str(techniques[0])
    return rec


def _parser_for(path: str) -> Callable[[str], LogRecord | None]:
    """Pick the parser for a remote log file from its path."""
    if path.endswith(".json") or "suricata" in path:
        return parse_eve_line
    if "apache" in path or "access" in path:
        return parse_apache_line
    return parse_sshd_line


# ---------------------------------------------------------------------------
# SSH transport
# ---------------------------------------------------------------------------

# Upper bound on one read, so a large backlog (first start, an eve.json
# burst) is consumed over several cycles rather than all in memory.
_MAX_READ = 5 * 1024 * 1024

_PERMISSION_HINT = (
    " - the SSH user cannot read this log. Run scripts/setup/setup_target.sh"
    " on the target and set LOG_READ_HELPER in config.env (see docs/architecture.md)."
)


@dataclass
class _RemoteFile:
    """Tracks read progress through one remote log file."""
    path: str
    offset: int = 0
    # Skip the file's existing contents on the first poll. Used for
    # eve.json, which is large and mostly old history when we connect.
    start_at_end: bool = False
    primed: bool = False      # offset is known (read before, or restored)


class SSHLogCollector:
    """Tails log files on the target VM over SSH.

    Each poll reads only the bytes appended since the last poll. The
    caller gets an iterator of LogRecord objects per cycle.
    """

    def __init__(
        self,
        host: str | None = None,
        user: str | None = None,
        key_path: str | None = None,
        port: int | None = None,
        log_paths: list[str] | None = None,
        read_helper: str | None = None,
        db: "Database | None" = None,
    ) -> None:
        self.host = host or settings.target_ip
        self.user = user or settings.ssh_user
        self.key_path = key_path or settings.ssh_key_path
        self.port = port or settings.ssh_port
        paths = log_paths or [settings.apache_log_path, settings.sshd_log_path]
        self.files = [_RemoteFile(p) for p in paths]
        if log_paths is None and settings.suricata_enabled:
            self.files.append(
                _RemoteFile(settings.suricata_eve_path, start_at_end=True)
            )
        self.db = db
        if db is not None:
            for f in self.files:
                saved = db.get_offset(f.path)
                if saved is not None:
                    # resume where the last run stopped; a file that shrank
                    # meanwhile is caught by the rotation check on read
                    f.offset = saved
                    f.primed = True
        self._client = None
        self._backoff = 5  # seconds; doubles on each failed reconnect
        self.read_helper = (
            settings.log_read_helper if read_helper is None else read_helper
        )

    # -- connection -----------------------------------------------------------

    def _connect(self) -> None:
        if paramiko is None:
            raise RuntimeError(
                "paramiko is not installed; run: pip install -r requirements.txt"
            )
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self.host,
            port=self.port,
            username=self.user,
            key_filename=self.key_path or None,
            timeout=10,
            banner_timeout=10,
        )
        self._client = client
        self._backoff = 5
        log.info("connected to %s as %s", self.host, self.user)

    def _ensure_connected(self) -> None:
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return
        self._connect()

    # -- reading --------------------------------------------------------------

    def _command(self, action: str, remote_path: str, offset: int = 0) -> str:
        """Shell command for "size" or "read" on the target.

        With LOG_READ_HELPER set, reads go through that root-owned helper via
        `sudo -n` (it only allows the configured log files). Reads are capped
        per cycle so a big backlog is consumed over several polls.
        """
        path = shlex.quote(remote_path)
        if self.read_helper:
            helper = f"sudo -n {shlex.quote(self.read_helper)}"
            if action == "size":
                return f"{helper} size {path}"
            return f"{helper} read {path} {int(offset)} | head -c {_MAX_READ}"
        if action == "size":
            return f"stat -c %s {path} 2>/dev/null || echo 0"
        # tail -c +N is 1-indexed, hence the +1
        return f"tail -c +{int(offset) + 1} {path} | head -c {_MAX_READ}"

    def _remote_size(self, remote_path: str) -> int:
        """Current size in bytes of a remote file (0 if missing)."""
        assert self._client is not None
        _, stdout, stderr = self._client.exec_command(
            self._command("size", remote_path), timeout=30
        )
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        if err:
            log.warning("size check failed for %s: %s", remote_path, err)
        try:
            return int(out or "0")
        except ValueError:
            return 0

    def _read_new_bytes(self, remote_path: str, offset: int) -> tuple[str, int]:
        """Return (complete new lines, new_offset) for one remote file.

        The offset only ever advances by bytes actually consumed, and only
        up to the last newline. So a file that grows between the size check
        and the read is not re-read next time (no duplicate events), a line
        still being written is left for the next poll instead of being
        parsed in two broken halves, and a read that fails (e.g. permission
        denied) is retried rather than silently skipped.
        """
        assert self._client is not None
        # remote size first, to detect rotation
        size = self._remote_size(remote_path)

        if size < offset:
            # file shrank: rotated. start over from the beginning.
            log.info("log rotation detected for %s", remote_path)
            offset = 0

        if size == offset:
            return "", offset

        _, stdout, stderr = self._client.exec_command(
            self._command("read", remote_path, offset), timeout=30
        )
        raw = stdout.read()
        err = stderr.read().decode(errors="replace").strip()

        end = raw.rfind(b"\n")
        if end < 0:
            if err:
                hint = _PERMISSION_HINT if "denied" in err.lower() else ""
                log.error("cannot read %s: %s%s", remote_path, err, hint)
            return "", offset
        if err:
            log.warning("read warning on %s: %s", remote_path, err)
        consumed = raw[: end + 1]
        return consumed.decode("utf-8", errors="replace"), offset + len(consumed)

    def poll(self) -> list[LogRecord]:
        """Read new lines from every tracked file and parse them.

        Connection problems are logged, not raised: the orchestrator
        decides when to retry.
        """
        try:
            self._ensure_connected()
        except Exception as exc:  # network down, VM off, auth broken
            log.warning("cannot reach %s: %s (retry in %ds)",
                        self.host, exc, self._backoff)
            self._client = None
            time.sleep(self._backoff)
            self._backoff = min(self._backoff * 2, 300)
            return []

        records: list[LogRecord] = []
        for f in self.files:
            try:
                if f.start_at_end and not f.primed:
                    self._advance(f, self._remote_size(f.path))
                    continue
                text, new_offset = self._read_new_bytes(f.path, f.offset)
            except Exception as exc:
                log.warning("read failed on %s: %s", f.path, exc)
                self._client = None  # force reconnect next cycle
                break
            self._advance(f, new_offset)
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                rec = _parser_for(f.path)(line)
                if rec is not None:
                    records.append(rec)
        return records

    def _advance(self, f: _RemoteFile, offset: int) -> None:
        """Move *f* to *offset* and, with a database, remember it."""
        if offset == f.offset and f.primed:
            return
        f.offset = offset
        f.primed = True
        if self.db is not None:
            self.db.set_offset(f.path, offset)

    def collect_forever(
        self,
        on_record: Callable[[LogRecord], None],
        interval: float | None = None,
    ) -> Iterator[None]:
        """Endless collection loop. Calls on_record for each new record."""
        interval = interval or settings.collect_interval
        while True:
            records = self.poll()
            for rec in records:
                on_record(rec)
            if records:
                log.info("collected %d new log lines", len(records))
            yield
            time.sleep(interval)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
