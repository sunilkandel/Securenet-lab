"""
Alert delivery for SecureNet Lab.

Telegram is the primary channel (fast, free, works on a phone). SMTP is
kept as a fallback for lab environments where Telegram is blocked. Both
channels are optional: if neither is configured, alerts are logged and
recorded in the DB as failed so nothing is silently lost.

Cooldowns live here too. The detector already rate-limits per event
type, but this layer applies a final per-IP cooldown so a host that
triggers several different rules at once does not flood the chat.
"""

from __future__ import annotations

import html
import smtplib
import time
from datetime import datetime, timezone
from email.message import EmailMessage

import requests

from src.config import settings
from src.logging_setup import get_logger
from src.models import Alert, AlertChannel, AlertStatus, Event, ThreatIntel
from src.storage import Database

log = get_logger(__name__)

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"

_SEVERITY_EMOJI = {
    "low": "ℹ️",
    "medium": "⚠️",
    "high": "🟠",
    "critical": "🔴",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AlertManager:
    """Formats and delivers alerts, with per-IP cooldown."""

    def __init__(
        self,
        db: Database,
        telegram_token: str | None = None,
        telegram_chat_id: str | None = None,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        alert_from: str | None = None,
        alert_to: str | None = None,
        cooldown: int | None = None,
    ) -> None:
        # Config snapshotted at construction so alert behaviour is fixed
        # for the life of the process and trivially testable.
        self.db = db
        self.telegram_token = (
            settings.telegram_bot_token if telegram_token is None else telegram_token
        )
        self.telegram_chat_id = (
            settings.telegram_chat_id
            if telegram_chat_id is None
            else telegram_chat_id
        )
        self.smtp_host = settings.smtp_host if smtp_host is None else smtp_host
        self.smtp_port = settings.smtp_port if smtp_port is None else smtp_port
        self.alert_from = settings.alert_from if alert_from is None else alert_from
        self.alert_to = settings.alert_to if alert_to is None else alert_to
        self.cooldown = settings.alert_cooldown if cooldown is None else cooldown
        self._last_sent: dict[str, float] = {}  # ip -> epoch

    # -- public API ------------------------------------------------------------

    def send(self, event: Event, intel: ThreatIntel | None = None) -> list[Alert]:
        """Deliver an alert for *event* over every configured channel.

        Returns the Alert records created (one per attempted channel).
        Suppressed by the cooldown; returns an empty list in that case.
        """
        now = time.time()
        last = self._last_sent.get(event.source_ip, 0.0)
        if now - last < self.cooldown:
            return []
        self._last_sent[event.source_ip] = now

        alerts: list[Alert] = []
        if self.telegram_token and self.telegram_chat_id:
            alerts.append(self._send_telegram(event, intel))
        if self.smtp_host and self.alert_to:
            alerts.append(self._send_email(event, intel))

        if not alerts:
            log.info(
                "alert for %s not delivered: no channel configured",
                event.source_ip,
            )
        return alerts

    def _redact(self, text: str) -> str:
        """Strip the bot token: it is part of the API URL, and requests
        puts that URL in its exception messages, i.e. in our logs."""
        if self.telegram_token:
            text = text.replace(self.telegram_token, "<redacted>")
        return text

    # -- message formatting ------------------------------------------------------

    def format_message(self, event: Event, intel: ThreatIntel | None) -> str:
        """Human-readable alert body, shared by both channels."""
        emoji = _SEVERITY_EMOJI.get(event.severity.value, "⚠️")
        lines = [
            f"{emoji} SecureNet alert: {event.event_type.value}",
            f"Source IP: {event.source_ip}",
            f"Severity: {event.severity.value}",
        ]
        if event.mitre_technique:
            lines.append(f"MITRE: {event.mitre_technique}")
        if intel is not None:
            lines.append(
                f"AbuseIPDB score: {intel.abuse_confidence_score:.0f}/100"
            )
            if intel.country or intel.isp:
                lines.append(
                    f"Origin: {intel.country or '?'} / {intel.isp or 'unknown ISP'}"
                )
        for key, value in event.details.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:5])
            lines.append(f"{key}: {value}")
        lines.append(f"Time: {event.timestamp}")
        return "\n".join(lines)

    # -- channels ------------------------------------------------------------------

    def _send_telegram(self, event: Event, intel: ThreatIntel | None) -> Alert:
        alert = Alert(event_id=event.id or 0, channel=AlertChannel.TELEGRAM)
        try:
            resp = requests.post(
                _TELEGRAM_API.format(token=self.telegram_token),
                json={
                    "chat_id": self.telegram_chat_id,
                    "text": html.escape(self.format_message(event, intel)),
                    "parse_mode": "HTML",
                },
                timeout=10,
            )
            if resp.status_code == 200:
                alert.status = AlertStatus.SENT
                alert.sent_at = _now()
            else:
                alert.status = AlertStatus.FAILED
                log.warning("Telegram returned %s: %s",
                            resp.status_code, resp.text[:200])
        except requests.RequestException as exc:
            alert.status = AlertStatus.FAILED
            log.warning("Telegram send failed: %s", self._redact(str(exc)))
        self.db.insert_alert(alert)
        return alert

    def _send_email(self, event: Event, intel: ThreatIntel | None) -> Alert:
        alert = Alert(event_id=event.id or 0, channel=AlertChannel.EMAIL)
        msg = EmailMessage()
        msg["Subject"] = (
            f"[SecureNet] {event.severity.value.upper()}: "
            f"{event.event_type.value} from {event.source_ip}"
        )
        msg["From"] = self.alert_from or "securenet@localhost"
        msg["To"] = self.alert_to
        msg.set_content(self.format_message(event, intel))
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
                smtp.send_message(msg)
            alert.status = AlertStatus.SENT
            alert.sent_at = _now()
        except (OSError, smtplib.SMTPException) as exc:
            alert.status = AlertStatus.FAILED
            log.warning("Email send failed: %s", exc)
        self.db.insert_alert(alert)
        return alert
