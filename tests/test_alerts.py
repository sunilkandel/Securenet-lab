"""
Tests for alert formatting and delivery.

Telegram and SMTP are mocked. The parts worth testing are message
content (an operator has to be able to act on it) and the cooldown that
stops a chat from being flooded.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.alerts.alerts import AlertManager
from src.models import Event, EventType, Severity, ThreatIntel
from src.storage import Database


@pytest.fixture
def db(tmp_path) -> Database:
    database = Database(tmp_path / "alerts.db")
    yield database
    database.close()


@pytest.fixture
def manager(db) -> AlertManager:
    # Explicit config instead of patching the frozen settings singleton.
    return AlertManager(
        db, telegram_token="tok", telegram_chat_id="123",
        smtp_host="", cooldown=0,
    )


def make_event(**kwargs) -> Event:
    defaults = dict(
        source_ip="1.2.3.4",
        event_type=EventType.SSH_BRUTE_FORCE,
        severity=Severity.HIGH,
        mitre_technique="T1110",
        details={"attempts": 12},
        id=1,
    )
    defaults.update(kwargs)
    return Event(**defaults)


def test_message_contains_actionable_fields(manager):
    intel = ThreatIntel(ip="1.2.3.4", abuse_confidence_score=88.0,
                        country="RU", isp="Evil Hosting")
    msg = manager.format_message(make_event(), intel)
    assert "1.2.3.4" in msg
    assert "ssh_brute_force" in msg
    assert "high" in msg
    assert "T1110" in msg
    assert "88" in msg


def test_message_renders_list_details(manager):
    msg = manager.format_message(make_event(details={"ports": [22, 80, 443]}), None)
    assert "22, 80, 443" in msg


@patch("src.alerts.alerts.requests.post")
def test_telegram_success_recorded(mock_post, manager, db):
    mock_post.return_value = MagicMock(status_code=200)
    alerts = manager.send(make_event())
    assert len(alerts) == 1
    assert alerts[0].status.value == "sent"
    assert db.recent_alerts(1)[0].status.value == "sent"


@patch("src.alerts.alerts.requests.post")
def test_telegram_failure_recorded(mock_post, manager, db):
    mock_post.return_value = MagicMock(status_code=400, text="bad request")
    alerts = manager.send(make_event())
    assert alerts[0].status.value == "failed"
    assert db.recent_alerts(1)[0].status.value == "failed"


@patch("src.alerts.alerts.requests.post")
def test_cooldown_suppresses_repeat(mock_post, db):
    manager = AlertManager(
        db, telegram_token="tok", telegram_chat_id="1", cooldown=1000
    )
    mock_post.return_value = MagicMock(status_code=200)

    first = manager.send(make_event())
    second = manager.send(make_event())
    assert len(first) == 1
    assert second == []
    assert mock_post.call_count == 1


def test_no_channel_configured_sends_nothing(db):
    manager = AlertManager(db, telegram_token="", smtp_host="")
    assert manager.send(make_event()) == []


@patch("src.alerts.alerts.smtplib.SMTP")
def test_email_channel(mock_smtp, db):
    manager = AlertManager(
        db, telegram_token="", smtp_host="10.0.0.1",
        alert_to="admin@local", alert_from="monitor@local", cooldown=0,
    )

    ctx = MagicMock()
    mock_smtp.return_value.__enter__.return_value = ctx

    alerts = manager.send(make_event())
    assert len(alerts) == 1
    assert alerts[0].channel.value == "email"
    assert ctx.send_message.called



@patch("src.alerts.alerts.requests.post")
def test_failed_send_does_not_leak_bot_token(mock_post, db, caplog):
    import requests
    token = "123456:SECRET-BOT-TOKEN"
    mock_post.side_effect = requests.ConnectionError(
        f"Max retries exceeded with url: /bot{token}/sendMessage"
    )
    manager = AlertManager(db, telegram_token=token, telegram_chat_id="1",
                           smtp_host="", cooldown=0)
    with caplog.at_level("WARNING"):
        alerts = manager.send(make_event())
    assert alerts[0].status.value == "failed"
    assert "Telegram send failed" in caplog.text
    assert token not in caplog.text
    assert "<redacted>" in caplog.text


@patch("src.alerts.alerts.requests.post")
def test_sent_at_is_delivery_time_not_event_time(mock_post, manager):
    from datetime import datetime, timedelta, timezone
    mock_post.return_value = MagicMock(status_code=200)
    old = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    alert = manager.send(make_event(timestamp=old))[0]
    sent = datetime.fromisoformat(alert.sent_at)
    assert datetime.now(timezone.utc) - sent < timedelta(minutes=1)
