"""
Centralized configuration management for SecureNet Lab.

Loads settings from config.env (dotenv format) with sensible defaults.
Every module imports settings from here — this is the single source of truth.

Usage:
    from src.config import settings

    print(settings.target_ip)        # "192.168.56.20"
    print(settings.brute_force_threshold)  # 5
"""

import os
from pathlib import Path
from dataclasses import dataclass, field

from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Project root — the directory that contains src/, config.env, etc.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env(key: str, default: str = "") -> str:
    """Read an environment variable, returning *default* if unset or empty."""
    return os.environ.get(key, default).strip() or default


def _env_int(key: str, default: int = 0) -> int:
    """Read an integer environment variable."""
    raw = _env(key, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(key: str, default: float = 0.0) -> float:
    """Read a float environment variable."""
    raw = _env(key, str(default))
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    """Read a boolean environment variable (true/false/1/0)."""
    raw = _env(key, str(default)).lower()
    return raw in ("true", "1", "yes", "on")


# ---------------------------------------------------------------------------
# Settings dataclass — one flat, typed namespace for everything
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Settings:
    """All configuration values for SecureNet Lab.

    Values are loaded once at import time from environment variables
    (which are populated from config.env via python-dotenv).
    """

    # -- Project paths --------------------------------------------------------
    project_root: Path = field(default_factory=lambda: _PROJECT_ROOT)
    data_dir: Path = field(default_factory=lambda: _PROJECT_ROOT / "data")
    logs_dir: Path = field(default_factory=lambda: _PROJECT_ROOT / "logs")

    # -- Target server (Rocky Linux VM) ---------------------------------------
    target_ip: str = ""
    ssh_user: str = ""
    ssh_port: int = 22
    ssh_key_path: str = ""

    # -- Log collection -------------------------------------------------------
    apache_log_path: str = "/var/log/httpd/access_log"
    sshd_log_path: str = "/var/log/secure"
    mail_log_path: str = "/var/log/maillog"
    collect_interval: int = 10          # seconds between collection cycles

    # -- Detection thresholds -------------------------------------------------
    brute_force_threshold: int = 5      # failed SSH attempts before alert
    port_scan_threshold: int = 20       # unique ports hit before alert
    web_enum_threshold: int = 10        # 404 responses before alert
    detection_window: int = 300         # seconds — sliding window for counts

    # -- Threat intelligence (AbuseIPDB) --------------------------------------
    abuseipdb_api_key: str = ""
    abuseipdb_cache_ttl: int = 3600     # seconds — re-check IPs after this
    abuseipdb_min_score: float = 50.0   # IPs scoring >= this are flagged

    # -- Auto-ban -------------------------------------------------------------
    auto_ban_enabled: bool = True
    ban_duration: int = 3600            # seconds — 0 = permanent
    firewall_backend: str = "firewalld" # "firewalld" or "ufw"

    # -- Alerts (Telegram) ----------------------------------------------------
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    alert_cooldown: int = 300           # seconds — min gap between same alerts

    # -- Alerts (Email) -------------------------------------------------------
    smtp_host: str = ""
    smtp_port: int = 25
    alert_from: str = ""
    alert_to: str = ""

    # -- REST API -------------------------------------------------------------
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False

    # -- Database -------------------------------------------------------------
    db_path: Path = field(
        default_factory=lambda: _PROJECT_ROOT / "data" / "securenet.db"
    )

    # -- Logging --------------------------------------------------------------
    log_level: str = "INFO"             # DEBUG, INFO, WARNING, ERROR
    log_format: str = "json"            # "json" or "text"
    log_file_enabled: bool = True


def load_settings(env_file: str | Path | None = None) -> Settings:
    """Load environment variables from *env_file* and return a Settings instance.

    If *env_file* is None, python-dotenv searches upward for config.env / .env.
    """
    if env_file is None:
        env_path = _PROJECT_ROOT / "config.env"
        if env_path.exists():
            load_dotenv(env_path, override=False)
        else:
            # Fallback: let dotenv search the usual places
            load_dotenv(override=False)
    else:
        load_dotenv(env_file, override=False)

    return Settings(
        # -- Target server
        target_ip=_env("TARGET_IP", "192.168.56.20"),
        ssh_user=_env("SSH_USER", ""),
        ssh_port=_env_int("SSH_PORT", 22),
        ssh_key_path=_env("SSH_KEY_PATH", ""),

        # -- Log collection
        apache_log_path=_env("APACHE_LOG_PATH", "/var/log/httpd/access_log"),
        sshd_log_path=_env("SSHD_LOG_PATH", "/var/log/secure"),
        mail_log_path=_env("MAIL_LOG_PATH", "/var/log/maillog"),
        collect_interval=_env_int("COLLECT_INTERVAL", 10),

        # -- Detection thresholds
        brute_force_threshold=_env_int("BRUTE_FORCE_THRESHOLD", 5),
        port_scan_threshold=_env_int("PORT_SCAN_THRESHOLD", 20),
        web_enum_threshold=_env_int("WEB_ENUM_THRESHOLD", 10),
        detection_window=_env_int("DETECTION_WINDOW", 300),

        # -- Threat intelligence
        abuseipdb_api_key=_env("ABUSEIPDB_API_KEY", ""),
        abuseipdb_cache_ttl=_env_int("ABUSEIPDB_CACHE_TTL", 3600),
        abuseipdb_min_score=_env_float("ABUSEIPDB_MIN_SCORE", 50.0),

        # -- Auto-ban
        auto_ban_enabled=_env_bool("AUTO_BAN_ENABLED", True),
        ban_duration=_env_int("BAN_DURATION", 3600),
        firewall_backend=_env("FIREWALL_BACKEND", "firewalld"),

        # -- Alerts — Telegram
        telegram_bot_token=_env("TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=_env("TELEGRAM_CHAT_ID", ""),

        # -- Alerts — Email
        smtp_host=_env("SMTP_HOST", ""),
        smtp_port=_env_int("SMTP_PORT", 25),
        alert_from=_env("ALERT_FROM", ""),
        alert_to=_env("ALERT_TO", ""),

        # -- REST API
        api_host=_env("API_HOST", "0.0.0.0"),
        api_port=_env_int("API_PORT", 8000),
        api_debug=_env_bool("API_DEBUG", False),

        # -- Logging
        log_level=_env("LOG_LEVEL", "INFO"),
        log_format=_env("LOG_FORMAT", "json"),
        log_file_enabled=_env_bool("LOG_FILE_ENABLED", True),
    )


# ---------------------------------------------------------------------------
# Module-level singleton — import and use directly
# ---------------------------------------------------------------------------
settings = load_settings()
