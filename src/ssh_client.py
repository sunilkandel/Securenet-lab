"""
SSH connections to the target VM, with host-key verification.

The collector and the auto-ban both log in to the target: one reads logs,
the other runs root firewall commands. Both connect through here, so the
target's identity is checked the same way everywhere.

The host key must already be in known_hosts (SSH_KNOWN_HOSTS, default
~/.ssh/known_hosts). `ssh-copy-id` during setup saves it after you confirm
the fingerprint. An unknown key is refused, and so is a changed one:
accepting any key would let another machine on the lab network (the Kali
VM, via ARP spoofing) pose as the target, feed it fake logs and receive
its firewall commands.
"""

from __future__ import annotations

import os

from src.config import settings

try:
    import paramiko
except ImportError:  # paramiko is optional for offline tests
    paramiko = None  # type: ignore[assignment]


class HostKeyError(Exception):
    """The target's host key is unknown or does not match known_hosts."""


def connect(
    host: str,
    port: int,
    user: str,
    key_path: str = "",
    known_hosts: str | None = None,
    timeout: float = 10,
) -> "paramiko.SSHClient":
    """Open an SSH session to *host*, verifying its key against known_hosts.

    Raises HostKeyError for an unknown or changed host key, RuntimeError if
    paramiko is missing, and paramiko/socket errors for anything else.
    """
    if paramiko is None:
        raise RuntimeError(
            "paramiko is not installed; run: pip install -r requirements.txt"
        )
    known_hosts = settings.ssh_known_hosts if known_hosts is None else known_hosts
    path = os.path.expanduser(known_hosts or "~/.ssh/known_hosts")

    client = paramiko.SSHClient()
    if os.path.exists(path):
        client.load_system_host_keys(path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    target = host if port == 22 else f"[{host}]:{port}"
    try:
        client.connect(
            host,
            port=port,
            username=user,
            key_filename=key_path or None,
            timeout=timeout,
            banner_timeout=timeout,
        )
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise HostKeyError(
            f"host key for {target} has CHANGED (got {exc.key.get_name()}). "
            f"If the target was reinstalled, remove the old key with "
            f"ssh-keygen -R '{target}' -f {path} and connect once with ssh; "
            f"otherwise something may be impersonating the target."
        ) from exc
    except paramiko.SSHException as exc:
        client.close()
        if "not found in known_hosts" in str(exc):
            raise HostKeyError(
                f"host key for {target} is not in {path}. Connect once with "
                f"ssh -p {port} {user}@{host} (or ssh-copy-id), check the "
                f"fingerprint and accept it."
            ) from exc
        raise
    return client
