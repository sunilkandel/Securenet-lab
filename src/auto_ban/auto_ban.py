"""
Firewall auto-ban for SecureNet Lab.

Pushes ban rules to the target VM over SSH using firewalld (Rocky
default) or ufw. Every ban is recorded in the database first, so the
system knows what it has banned and can expire or revoke rules later.

Design decisions:

- Bans are applied with a single SSH command; we never keep a session
  open longer than needed.
- Only literal IP addresses are ever banned, and never an address on
  the never-ban list (loopback, the target, NEVER_BAN). The IP comes
  from attack traffic and ends up in a root command on the target.
- Every remote command carries its own `sudo -n`, so sudoers can be
  limited to firewall-cmd/ufw and a missing rule fails fast instead
  of hanging on a password prompt.
- firewalld: temporary bans are runtime rules with `--timeout`, so the
  target lifts them itself even if this VM is down. firewalld rejects
  a timeout on a permanent rule, and `timeout=` is not rich-rule
  syntax. Permanent bans go into both saved and running config; no
  `--reload`, which would also wipe every timed ban.
- ufw has no timeouts: expiry is swept here, each pipeline cycle.
- If SSH is unreachable we mark the ban as failed in the DB and move
  on. The orchestrator will retry on the next cycle.
"""

from __future__ import annotations

import ipaddress
import shlex
from datetime import datetime, timedelta, timezone

from src.config import settings
from src.logging_setup import get_logger
from src.models import Ban, BanStatus
from src.storage import Database

log = get_logger(__name__)

try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore[assignment]


class AutoBan:
    """Applies and revokes firewall bans on the target VM."""

    def __init__(
        self,
        db: Database,
        backend: str | None = None,
        host: str | None = None,
        user: str | None = None,
        key_path: str | None = None,
        port: int | None = None,
        enabled: bool | None = None,
        ban_duration: int | None = None,
        never_ban: list[str] | None = None,
    ) -> None:
        # Config is snapshotted here rather than read from the settings
        # singleton on each call. Keeps the object testable without
        # mutating global state, and gives callers an explicit override.
        self.db = db
        self.backend = backend or settings.firewall_backend
        self.host = host or settings.target_ip
        self.user = user or settings.ssh_user
        self.key_path = key_path or settings.ssh_key_path
        self.port = port or settings.ssh_port
        self.enabled = settings.auto_ban_enabled if enabled is None else enabled
        self.ban_duration = (
            settings.ban_duration if ban_duration is None else ban_duration
        )
        entries = (
            settings.never_ban.split(",") if never_ban is None else never_ban
        )
        entries = [*entries, "127.0.0.0/8", "::1/128", self.host]
        self.protected = []
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            try:
                self.protected.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.warning("never-ban list: ignoring %r (not an IP/CIDR)", entry)

    # -- public API -------------------------------------------------------------

    def ban(self, ip: str, reason: str = "") -> Ban | None:
        """Ban *ip* on the target's firewall. Returns the Ban record.

        Skips work when auto-ban is disabled or the IP is already banned.
        """
        if not self.enabled:
            log.info("auto-ban disabled; would have banned %s", ip)
            return None

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            log.warning("refusing to ban %r: not an IP address", ip)
            return None
        if self.is_protected(addr):
            log.warning("refusing to ban %s: on the never-ban list", ip)
            return None
        ip = str(addr)  # normalized form, e.g. for IPv6

        existing = self.db.get_active_ban(ip)
        if existing:
            return existing

        expires_at = ""
        if self.ban_duration > 0:
            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(seconds=self.ban_duration)
            ).isoformat()

        ban = Ban(ip=ip, reason=reason, expires_at=expires_at)
        ban_id = self.db.insert_ban(ban)

        if self._apply_remote(ip, self.ban_duration):
            log.info("banned %s (%s)", ip, reason)
        else:
            # keep the record but mark it so an operator can see it failed
            self.db.set_ban_status(ban_id, BanStatus.REMOVED)
            log.error("failed to ban %s on %s", ip, self.host)
            return None
        return ban

    def is_protected(
        self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        """True if *addr* is loopback, the target, or on NEVER_BAN."""
        return any(
            addr.version == net.version and addr in net for net in self.protected
        )

    def unban(self, ip: str) -> bool:
        """Remove the firewall rule for *ip* and mark the DB row inactive."""
        ban = self.db.get_active_ban(ip)
        if ban is None:
            return False
        if self._remove_remote(ip):
            self.db.set_ban_status(ban.id, BanStatus.REMOVED)  # type: ignore[arg-type]
            log.info("unbanned %s", ip)
            return True
        return False

    def expire_old_bans(self) -> int:
        """Sweep the DB for expired temporary bans and remove their rules."""
        now = datetime.now(timezone.utc).isoformat()
        expired = [
            b for b in self.db.active_bans()
            if b.expires_at and b.expires_at <= now
        ]
        for ban in expired:
            if self._remove_remote(ban.ip):
                self.db.set_ban_status(ban.id, BanStatus.EXPIRED)  # type: ignore[arg-type]
                log.info("expired ban lifted for %s", ban.ip)
        return len(expired)

    # -- remote execution ---------------------------------------------------------

    def _ssh(self, command: str) -> bool:
        """Run shell *command* on the target. True on exit code 0.

        Commands carry their own `sudo -n` (see module docstring).
        """
        if paramiko is None:
            log.error("paramiko not installed; cannot manage remote firewall")
            return False
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.host,
                port=self.port,
                username=self.user,
                key_filename=self.key_path or None,
                timeout=10,
            )
            _, stdout, stderr = client.exec_command(command, timeout=30)
            rc = stdout.channel.recv_exit_status()
            err = stderr.read().decode().strip()
            client.close()
            if rc != 0:
                log.error("remote command failed (%d): %s", rc, err)
                return False
            return True
        except Exception as exc:
            log.error("SSH to %s failed: %s", self.host, exc)
            return False

    @staticmethod
    def _rich_rule(ip: str) -> str:
        family = "ipv6" if ipaddress.ip_address(ip).version == 6 else "ipv4"
        return f'rule family="{family}" source address="{ip}" drop'

    def _apply_remote(self, ip: str, duration: int) -> bool:
        if self.backend == "ufw":
            # prepend, not append: ufw matches rules in order, so a deny
            # added after an existing "allow 80" would never match.
            return self._ssh(f"sudo -n ufw prepend deny from {shlex.quote(ip)}")
        rule = shlex.quote(self._rich_rule(ip))
        if duration > 0:
            return self._ssh(
                f"sudo -n firewall-cmd --add-rich-rule={rule} --timeout={int(duration)}"
            )
        return self._ssh(
            f"sudo -n firewall-cmd --permanent --add-rich-rule={rule} "
            f"&& sudo -n firewall-cmd --add-rich-rule={rule}"
        )

    def _remove_remote(self, ip: str) -> bool:
        if self.backend == "ufw":
            return self._ssh(f"sudo -n ufw delete deny from {shlex.quote(ip)}")
        rule = shlex.quote(self._rich_rule(ip))
        # Safe to repeat: firewall-cmd exits 0 with a NOT_ENABLED warning
        # when the rule is already gone (e.g. a timed ban that expired).
        return self._ssh(
            f"sudo -n firewall-cmd --remove-rich-rule={rule} "
            f"&& sudo -n firewall-cmd --permanent --remove-rich-rule={rule}"
        )
