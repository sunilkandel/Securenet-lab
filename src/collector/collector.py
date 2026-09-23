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
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterator

from src.config import settings
from src.logging_setup import get_logger

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

    `kind` is "apache" or "sshd". Fields not relevant to the source are
    left at their defaults.
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
    raw: str = ""


# ---------------------------------------------------------------------------
# Apache combined-log parsing
# ---------------------------------------------------------------------------

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_apache_timestamp(raw: str) -> datetime | None:
    """Parse '10/Oct/2000:13:55:36 -0700' (timezone ignored, local time)."""
    try:
        date_part, time_part = raw.split(":", 1)
        day, mon, year = date_part.split("/")
        hh, mm, ss = time_part.split(" ")[0].split(":")
        return datetime(
            int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss)
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

    action = ""
    user = ""
    ip = ""

    if "Failed password for" in raw:
        action = "failed"
        after = raw.split("Failed password for", 1)[1]
        if after.startswith(" invalid user "):
            user = after.split(" invalid user ", 1)[1].split(" from ")[0]
        else:
            user = after.strip().split(" from ")[0]
        if " from " in after:
            ip = after.split(" from ", 1)[1].split(" ")[0]
    elif "Accepted password for" in raw or "Accepted publickey for" in raw:
        action = "accepted"
        after = raw.split(" for ", 1)[1]
        user = after.split(" from ")[0]
        if " from " in after:
            ip = after.split(" from ", 1)[1].split(" ")[0]
    elif "Invalid user" in raw:
        action = "invalid_user"
        after = raw.split("Invalid user", 1)[1]
        user = after.strip().split(" from ")[0]
        if " from " in after:
            ip = after.split(" from ", 1)[1].split(" ")[0]
    elif "Connection closed by" in raw or "Disconnected from" in raw:
        return None  # noise for our purposes
    else:
        return None

    if not ip:
        return None

    return LogRecord(
        kind="sshd",
        source_ip=ip,
        timestamp=timestamp,
        user=user,
        action=action,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# SSH transport
# ---------------------------------------------------------------------------

@dataclass
class _RemoteFile:
    """Tracks read progress through one remote log file."""
    path: str
    offset: int = 0


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
    ) -> None:
        self.host = host or settings.target_ip
        self.user = user or settings.ssh_user
        self.key_path = key_path or settings.ssh_key_path
        self.port = port or settings.ssh_port
        self.files = [
            _RemoteFile(p)
            for p in (
                log_paths
                or [settings.apache_log_path, settings.sshd_log_path]
            )
        ]
        self._client = None
        self._backoff = 5  # seconds; doubles on each failed reconnect

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

    def _read_new_bytes(self, remote_path: str, offset: int) -> tuple[str, int]:
        """Return (new_text, new_offset) for one remote file.

        Uses tail with a byte offset so we never re-read or re-parse old
        lines, even across reconnects. `tail -c +N` is 1-indexed, hence
        the +1.
        """
        assert self._client is not None
        # remote size first, to detect rotation
        _, stdout, _ = self._client.exec_command(
            f"stat -c %s {remote_path} 2>/dev/null || echo 0"
        )
        size = int(stdout.read().decode().strip() or "0")

        if size < offset:
            # file shrank: rotated. start over from the beginning.
            log.info("log rotation detected for %s", remote_path)
            offset = 0

        if size == offset:
            return "", offset

        _, stdout, stderr = self._client.exec_command(
            f"tail -c +{offset + 1} {remote_path}"
        )
        data = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode().strip()
        if err:
            log.warning("tail error on %s: %s", remote_path, err)
        return data, size

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
                text, new_offset = self._read_new_bytes(f.path, f.offset)
            except Exception as exc:
                log.warning("read failed on %s: %s", f.path, exc)
                self._client = None  # force reconnect next cycle
                break
            f.offset = new_offset
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                rec = (
                    parse_apache_line(line)
                    if "apache" in f.path or "access" in f.path
                    else parse_sshd_line(line)
                )
                if rec is not None:
                    records.append(rec)
        return records

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
