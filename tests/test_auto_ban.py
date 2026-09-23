"""
Tests for the firewall auto-ban module.

SSH is mocked out; what we care about is the bookkeeping (DB records,
duplicate suppression, expiry sweep) and that the right firewall command
is built for each backend.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.auto_ban.auto_ban import AutoBan
from src.models import Ban, BanStatus
from src.storage import Database


@pytest.fixture
def db(tmp_path) -> Database:
    database = Database(tmp_path / "ban.db")
    yield database
    database.close()


@pytest.fixture
def banner(db) -> AutoBan:
    # Explicit config rather than patching the frozen settings singleton.
    return AutoBan(
        db, backend="firewalld", host="10.0.0.1",
        enabled=True, ban_duration=3600,
    )


@patch.object(AutoBan, "_apply_remote", return_value=True)
def test_ban_creates_active_record(mock_apply, banner, db):
    ban = banner.ban("1.2.3.4", "ssh_brute_force")
    assert ban is not None
    assert db.get_active_ban("1.2.3.4") is not None
    assert mock_apply.call_count == 1


@patch.object(AutoBan, "_apply_remote", return_value=True)
def test_duplicate_ban_is_noop(mock_apply, banner, db):
    banner.ban("1.2.3.4")
    banner.ban("1.2.3.4")
    assert mock_apply.call_count == 1
    assert len(db.active_bans()) == 1


@patch.object(AutoBan, "_apply_remote", return_value=False)
def test_failed_remote_ban_leaves_no_active_record(mock_apply, banner, db):
    result = banner.ban("1.2.3.4")
    assert result is None
    assert db.active_bans() == []


@patch.object(AutoBan, "_apply_remote", return_value=True)
def test_unban_marks_removed(mock_apply, banner, db):
    banner.ban("1.2.3.4")
    with patch.object(AutoBan, "_remove_remote", return_value=True):
        assert banner.unban("1.2.3.4") is True
    assert db.get_active_ban("1.2.3.4") is None


def test_unban_unknown_ip_returns_false(banner):
    assert banner.unban("9.9.9.9") is False


@patch.object(AutoBan, "_remove_remote", return_value=True)
def test_expire_old_bans_sweeps(mock_remove, banner, db):
    expired = Ban(
        ip="1.2.3.4",
        expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
    )
    future = Ban(
        ip="5.6.7.8",
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    )
    db.insert_ban(expired)
    db.insert_ban(future)

    count = banner.expire_old_bans()
    assert count == 1
    assert db.get_active_ban("1.2.3.4") is None
    assert db.get_active_ban("5.6.7.8") is not None


def test_disabled_auto_ban_returns_none(db):
    banner = AutoBan(db, enabled=False)
    assert banner.ban("1.2.3.4") is None
    assert db.active_bans() == []


def test_ufw_command_shape(db):
    # Needs its own instance: the shared `banner` fixture is pinned to the
    # firewalld backend, so this has to build a ufw-backed one explicitly.
    banner = AutoBan(db, backend="ufw", host="10.0.0.1", enabled=True)
    with patch.object(banner, "_ssh", return_value=True) as mock_ssh:
        banner._apply_remote("1.2.3.4", 3600)
        assert "sudo -n ufw prepend deny from 1.2.3.4" in mock_ssh.call_args[0][0]


def test_firewalld_command_uses_timeout(db):
    banner = AutoBan(db, backend="firewalld", enabled=True)
    with patch.object(banner, "_ssh", return_value=True) as mock_ssh:
        banner._apply_remote("1.2.3.4", 3600)
        cmd = mock_ssh.call_args[0][0]
        assert "firewall-cmd" in cmd
        assert "1.2.3.4" in cmd
        assert "--timeout=3600" in cmd
        # firewalld rejects a timeout on a permanent rule
        assert "--permanent" not in cmd


def test_permanent_ban_has_no_timeout(db):
    banner = AutoBan(db, backend="firewalld", enabled=True)
    with patch.object(banner, "_ssh", return_value=True) as mock_ssh:
        banner._apply_remote("1.2.3.4", 0)
        cmd = mock_ssh.call_args[0][0]
        assert "timeout" not in cmd
        assert "--permanent" in cmd
        # a reload would wipe every timed runtime ban
        assert "--reload" not in cmd


def _commands(banner, fn, *args):
    with patch.object(banner, "_ssh", return_value=True) as mock_ssh:
        fn(*args)
        return [c[0][0] for c in mock_ssh.call_args_list]


@pytest.mark.parametrize("backend", ["firewalld", "ufw"])
@pytest.mark.parametrize("duration", [0, 3600])
def test_every_remote_step_runs_with_sudo_n(db, backend, duration):
    banner = AutoBan(db, backend=backend, host="10.0.0.1", enabled=True)
    cmds = _commands(banner, banner._apply_remote, "1.2.3.4", duration)
    cmds += _commands(banner, banner._remove_remote, "1.2.3.4")
    for cmd in cmds:
        for step in cmd.split("&&"):
            assert step.strip().startswith("sudo -n "), step


@patch.object(AutoBan, "_apply_remote", return_value=True)
def test_invalid_ip_is_never_banned(mock_apply, banner, db):
    for bad in ["$(id>/tmp/pwned)", "1.2.3.4;reboot", "x'y", "", "evil.com"]:
        assert banner.ban(bad) is None
    assert mock_apply.call_count == 0
    assert db.active_bans() == []


@patch.object(AutoBan, "_apply_remote", return_value=True)
def test_never_ban_list(mock_apply, db):
    banner = AutoBan(db, host="192.168.56.20", enabled=True,
                     never_ban=["192.168.56.30", "10.9.0.0/16", "not-an-ip"])
    for ip in ["127.0.0.1", "::1", "192.168.56.20", "192.168.56.30", "10.9.4.4"]:
        assert banner.ban(ip) is None, ip
    assert mock_apply.call_count == 0
    assert banner.ban("192.168.56.10") is not None  # the attacker still is


def test_rich_rule_quotes_and_family(db):
    banner = AutoBan(db, backend="firewalld", host="10.0.0.1", enabled=True)
    assert banner._rich_rule("1.2.3.4") == 'rule family="ipv4" source address="1.2.3.4" drop'
    assert 'family="ipv6"' in banner._rich_rule("2001:db8::1")
    cmd = _commands(banner, banner._apply_remote, "1.2.3.4", 60)[0]
    # the whole rule is one shell-quoted argument
    assert "--add-rich-rule='rule family=\"ipv4\" source address=\"1.2.3.4\" drop'" in cmd


def test_firewalld_removal_covers_runtime_and_permanent(db):
    banner = AutoBan(db, backend="firewalld", host="10.0.0.1", enabled=True)
    cmd = _commands(banner, banner._remove_remote, "1.2.3.4")[0]
    assert "--remove-rich-rule" in cmd and "--permanent --remove-rich-rule" in cmd
