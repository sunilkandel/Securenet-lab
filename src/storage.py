"""
SQLite storage layer for SecureNet Lab.

One database file, one module. All tables are created on first use, so a
fresh clone works without any migration step. The API server and the
pipeline share a single connection guarded by a lock, with WAL mode on
so the dashboard can read while the pipeline writes.

Usage:
    from src.storage import Database

    db = Database(settings.db_path)
    event_id = db.insert_event(event)
    recent = db.recent_events(limit=50)
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.models import (
    Alert,
    AlertChannel,
    AlertStatus,
    Ban,
    BanStatus,
    Event,
    EventType,
    IPInfo,
    Severity,
    ThreatIntel,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip       TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    raw_log         TEXT DEFAULT '',
    mitre_technique TEXT DEFAULT '',
    details         TEXT DEFAULT '{}',
    timestamp       TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    reason     TEXT DEFAULT '',
    banned_at  TEXT NOT NULL,
    expires_at TEXT DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS alerts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    channel  TEXT NOT NULL,
    status   TEXT NOT NULL DEFAULT 'pending',
    sent_at  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS threat_intel (
    ip                     TEXT PRIMARY KEY,
    abuse_confidence_score REAL DEFAULT 0,
    country                TEXT DEFAULT '',
    isp                    TEXT DEFAULT '',
    usage_type             TEXT DEFAULT '',
    lookup_result          TEXT DEFAULT '{}',
    last_checked           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_info (
    ip          TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    event_count INTEGER DEFAULT 0,
    risk_score  REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_time ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans (ip);
CREATE INDEX IF NOT EXISTS idx_bans_status ON bans (status);
"""


class Database:
    """Thin, thread-safe wrapper around a SQLite database.

    All methods accept and return the dataclasses from src.models, so
    callers never have to think about SQL or JSON columns.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, timeout=30
        )
        self._conn.row_factory = sqlite3.Row
        # WAL lets the FastAPI process read while the pipeline writes.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- internal helpers ---------------------------------------------------

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- events ---------------------------------------------------------------

    def insert_event(self, event: Event) -> int:
        """Persist an Event and return its new row id."""
        cur = self._execute(
            """
            INSERT INTO events
                (source_ip, event_type, severity, raw_log,
                 mitre_technique, details, timestamp, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.source_ip,
                event.event_type.value,
                event.severity.value,
                event.raw_log,
                event.mitre_technique,
                json.dumps(event.details),
                event.timestamp,
                event.created_at,
            ),
        )
        event.id = int(cur.lastrowid)
        return event.id

    def _row_to_event(self, row: sqlite3.Row) -> Event:
        return Event(
            id=row["id"],
            source_ip=row["source_ip"],
            event_type=EventType(row["event_type"]),
            severity=Severity(row["severity"]),
            raw_log=row["raw_log"],
            mitre_technique=row["mitre_technique"],
            details=json.loads(row["details"] or "{}"),
            timestamp=row["timestamp"],
            created_at=row["created_at"],
        )

    def recent_events(self, limit: int = 100) -> list[Event]:
        """Most recent events first."""
        rows = self._query(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [self._row_to_event(r) for r in rows]

    def events_by_ip(self, ip: str, limit: int = 100) -> list[Event]:
        rows = self._query(
            "SELECT * FROM events WHERE source_ip = ? "
            "ORDER BY id DESC LIMIT ?",
            (ip, limit),
        )
        return [self._row_to_event(r) for r in rows]

    def count_events_by_type(self) -> dict[str, int]:
        """Aggregate counts used by the dashboard and the R reports."""
        rows = self._query(
            "SELECT event_type, COUNT(*) AS n FROM events "
            "GROUP BY event_type ORDER BY n DESC"
        )
        return {r["event_type"]: r["n"] for r in rows}

    def count_events_by_severity(self) -> dict[str, int]:
        rows = self._query(
            "SELECT severity, COUNT(*) AS n FROM events GROUP BY severity"
        )
        return {r["severity"]: r["n"] for r in rows}

    def events_per_day(self, days: int = 14) -> list[dict[str, Any]]:
        """Daily event counts for the last *days* days (for charts)."""
        rows = self._query(
            """
            SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS n
            FROM events
            WHERE timestamp >= datetime('now', ?)
            GROUP BY day ORDER BY day
            """,
            (f"-{days} days",),
        )
        return [{"day": r["day"], "count": r["n"]} for r in rows]

    def top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        # Severity is stored as text, and MAX() on text is alphabetical
        # ("critical" < "high" < "low" < "medium"), which would report a
        # host with a critical and a medium event as "medium". Rank first.
        rows = self._query(
            """
            SELECT source_ip, COUNT(*) AS n,
                   MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                     WHEN 'medium' THEN 2 WHEN 'low' THEN 1
                                     ELSE 0 END) AS worst
            FROM events
            GROUP BY source_ip ORDER BY n DESC LIMIT ?
            """,
            (limit,),
        )
        names = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        return [
            {
                "ip": r["source_ip"],
                "count": r["n"],
                "worst_severity": names.get(r["worst"], "unknown"),
            }
            for r in rows
        ]

    # -- bans -----------------------------------------------------------------

    def insert_ban(self, ban: Ban) -> int:
        cur = self._execute(
            """
            INSERT INTO bans (ip, reason, banned_at, expires_at, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ban.ip, ban.reason, ban.banned_at, ban.expires_at, ban.status.value),
        )
        ban.id = int(cur.lastrowid)
        return ban.id

    def _row_to_ban(self, row: sqlite3.Row) -> Ban:
        return Ban(
            id=row["id"],
            ip=row["ip"],
            reason=row["reason"],
            banned_at=row["banned_at"],
            expires_at=row["expires_at"],
            status=BanStatus(row["status"]),
        )

    def active_bans(self) -> list[Ban]:
        rows = self._query(
            "SELECT * FROM bans WHERE status = 'active' ORDER BY id DESC"
        )
        return [self._row_to_ban(r) for r in rows]

    def get_active_ban(self, ip: str) -> Ban | None:
        rows = self._query(
            "SELECT * FROM bans WHERE ip = ? AND status = 'active' "
            "ORDER BY id DESC LIMIT 1",
            (ip,),
        )
        return self._row_to_ban(rows[0]) if rows else None

    def set_ban_status(self, ban_id: int, status: BanStatus) -> None:
        self._execute(
            "UPDATE bans SET status = ? WHERE id = ?", (status.value, ban_id)
        )

    # -- alerts ---------------------------------------------------------------

    def insert_alert(self, alert: Alert) -> int:
        cur = self._execute(
            """
            INSERT INTO alerts (event_id, channel, status, sent_at)
            VALUES (?, ?, ?, ?)
            """,
            (alert.event_id, alert.channel.value, alert.status.value, alert.sent_at),
        )
        alert.id = int(cur.lastrowid)
        return alert.id

    def recent_alerts(self, limit: int = 50) -> list[Alert]:
        rows = self._query(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [
            Alert(
                id=r["id"],
                event_id=r["event_id"],
                channel=AlertChannel(r["channel"]),
                status=AlertStatus(r["status"]),
                sent_at=r["sent_at"],
            )
            for r in rows
        ]

    # -- threat intel -----------------------------------------------------------

    def upsert_threat_intel(self, intel: ThreatIntel) -> None:
        self._execute(
            """
            INSERT INTO threat_intel
                (ip, abuse_confidence_score, country, isp, usage_type,
                 lookup_result, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                abuse_confidence_score = excluded.abuse_confidence_score,
                country                = excluded.country,
                isp                    = excluded.isp,
                usage_type             = excluded.usage_type,
                lookup_result          = excluded.lookup_result,
                last_checked           = excluded.last_checked
            """,
            (
                intel.ip,
                intel.abuse_confidence_score,
                intel.country,
                intel.isp,
                intel.usage_type,
                json.dumps(intel.lookup_result),
                intel.last_checked,
            ),
        )

    def get_threat_intel(self, ip: str) -> ThreatIntel | None:
        rows = self._query(
            "SELECT * FROM threat_intel WHERE ip = ?", (ip,)
        )
        if not rows:
            return None
        r = rows[0]
        return ThreatIntel(
            ip=r["ip"],
            abuse_confidence_score=r["abuse_confidence_score"],
            country=r["country"],
            isp=r["isp"],
            usage_type=r["usage_type"],
            lookup_result=json.loads(r["lookup_result"] or "{}"),
            last_checked=r["last_checked"],
        )

    # -- ip info --------------------------------------------------------------

    def touch_ip(self, ip: str, now: str, risk_score: float = 0.0) -> None:
        """Record that *ip* was seen again; bump its counter and risk."""
        self._execute(
            """
            INSERT INTO ip_info (ip, first_seen, last_seen, event_count, risk_score)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen   = excluded.last_seen,
                event_count = event_count + 1,
                risk_score  = MAX(risk_score, excluded.risk_score)
            """,
            (ip, now, now, risk_score),
        )

    def get_ip_info(self, ip: str) -> IPInfo | None:
        rows = self._query("SELECT * FROM ip_info WHERE ip = ?", (ip,))
        if not rows:
            return None
        r = rows[0]
        return IPInfo(
            ip=r["ip"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            event_count=r["event_count"],
            risk_score=r["risk_score"],
        )

    # -- dashboard stats ------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """One-shot stats bundle for the API / dashboard header."""
        total_events = self._query("SELECT COUNT(*) AS n FROM events")[0]["n"]
        active = len(self.active_bans())
        unique_ips = self._query(
            "SELECT COUNT(DISTINCT source_ip) AS n FROM events"
        )[0]["n"]
        last_row = self._query(
            "SELECT timestamp FROM events ORDER BY id DESC LIMIT 1"
        )
        return {
            "total_events": total_events,
            "active_bans": active,
            "unique_attackers": unique_ips,
            "last_event_at": last_row[0]["timestamp"] if last_row else None,
            "events_by_type": self.count_events_by_type(),
            "events_by_severity": self.count_events_by_severity(),
        }
