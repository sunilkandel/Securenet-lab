"""
SecureNet Lab pipeline orchestrator.

Wires the five components into one loop:

    collect -> detect -> threat intel -> auto-ban -> alert
                 |
                 +--> every event is stored in SQLite for the API/R

Runs as a long-lived process. SIGINT/SIGTERM shut it down cleanly.
Each cycle is wrapped so a single bad record or a network blip logs a
warning and the loop continues; nothing in a monitoring pipeline should
be able to kill the monitor.

Usage:
    python -m src.orchestrator.main
    python -m src.orchestrator.main --once   # single cycle, for cron/tests
"""

from __future__ import annotations

import argparse
import signal
import sys
import time

from src.alerts.alerts import AlertManager
from src.auto_ban.auto_ban import AutoBan
from src.collector.collector import SSHLogCollector
from src.config import settings
from src.detector.detector import Detector
from src.logging_setup import get_logger
from src.models import Event, Severity
from src.storage import Database
from src.threat_intel.threat_intel import ThreatIntelClient

log = get_logger(__name__)

# Severities that justify an automatic firewall ban on their own.
_BAN_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}


class Pipeline:
    """One collection-detection-response cycle, repeated.

    Components are injected so the whole loop can be exercised with
    fakes in tests. Defaults build the real thing from settings.
    """

    def __init__(
        self,
        db: Database | None = None,
        collector: SSHLogCollector | None = None,
        detector: Detector | None = None,
        intel: ThreatIntelClient | None = None,
        banner: AutoBan | None = None,
        alerter: AlertManager | None = None,
        interval: int | None = None,
    ) -> None:
        self.db = db or Database(settings.db_path)
        self.collector = collector or SSHLogCollector()
        self.detector = detector or Detector()
        self.intel = intel or ThreatIntelClient(self.db)
        self.banner = banner or AutoBan(self.db)
        self.alerter = alerter or AlertManager(self.db)
        self.interval = interval or settings.collect_interval
        self._stop = False

    # -- one cycle ------------------------------------------------------------

    def run_once(self) -> dict[str, int]:
        """Run a single pipeline cycle. Returns counts for logging/tests."""
        stats = {"collected": 0, "events": 0, "bans": 0, "alerts": 0}

        records = self.collector.poll()
        stats["collected"] = len(records)

        events = self.detector.process_many(records)
        for event in events:
            try:
                self._handle_event(event, stats)
            except Exception:
                log.exception("failed to handle event %s", event.event_type)

        stats["bans"] += self.banner.expire_old_bans()
        return stats

    # -- event handling ---------------------------------------------------------

    def _handle_event(self, event: Event, stats: dict[str, int]) -> None:
        self.db.insert_event(event)
        self.db.touch_ip(
            event.source_ip,
            event.timestamp,
            risk_score=self._severity_score(event.severity),
        )
        stats["events"] += 1

        intel = self.intel.check(event.source_ip)

        # is_malicious() does its own check() call internally (cached), so
        # it does not need to be gated on `intel` being non-None here — a
        # missed/absent cache entry for the alert-message lookup should not
        # block the independent malicious-IP determination.
        should_ban = (
            event.severity in _BAN_SEVERITIES
            or self.intel.is_malicious(event.source_ip)
        )
        if should_ban:
            reason = f"{event.event_type.value} ({event.severity.value})"
            if self.banner.ban(event.source_ip, reason):
                stats["bans"] += 1

        sent = self.alerter.send(event, intel)
        stats["alerts"] += sum(1 for a in sent if a.status.value == "sent")

    @staticmethod
    def _severity_score(severity: Severity) -> float:
        return {
            Severity.LOW: 10.0,
            Severity.MEDIUM: 40.0,
            Severity.HIGH: 70.0,
            Severity.CRITICAL: 95.0,
        }[severity]

    # -- main loop ------------------------------------------------------------

    def run(self) -> None:
        """Run forever until a termination signal arrives."""
        def _stop(signum, frame):  # noqa: ANN001
            log.info("received signal %d, shutting down", signum)
            self._stop = True

        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)

        log.info(
            "SecureNet pipeline started (target=%s, interval=%ds)",
            settings.target_ip, self.interval,
        )
        while not self._stop:
            started = time.time()
            stats = self.run_once()
            if stats["collected"] or stats["events"]:
                log.info("cycle: %s", stats)
            elapsed = time.time() - started
            time.sleep(max(0.0, self.interval - elapsed))

        self.collector.close()
        self.db.close()
        log.info("pipeline stopped")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecureNet Lab pipeline")
    parser.add_argument(
        "--once",
        action="store_true",
        help="run a single collection cycle and exit (useful for cron)",
    )
    args = parser.parse_args(argv)

    pipeline = Pipeline()
    if args.once:
        stats = pipeline.run_once()
        print(f"cycle complete: {stats}")
        return 0

    pipeline.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
