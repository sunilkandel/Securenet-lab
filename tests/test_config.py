"""Tests for the centralized configuration module."""

import os
import tempfile
from pathlib import Path

import pytest


# All env keys that load_settings reads — we save/restore these between tests
# to prevent cross-test contamination (load_dotenv uses override=False).
_ENV_KEYS = [
    "TARGET_IP", "SSH_USER", "SSH_PORT", "SSH_KEY_PATH",
    "APACHE_LOG_PATH", "SSHD_LOG_PATH", "MAIL_LOG_PATH", "COLLECT_INTERVAL",
    "BRUTE_FORCE_THRESHOLD", "PORT_SCAN_THRESHOLD", "WEB_ENUM_THRESHOLD",
    "DETECTION_WINDOW",
    "ABUSEIPDB_API_KEY", "ABUSEIPDB_CACHE_TTL", "ABUSEIPDB_MIN_SCORE",
    "AUTO_BAN_ENABLED", "BAN_DURATION", "FIREWALL_BACKEND",
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
    "SMTP_HOST", "SMTP_PORT", "ALERT_FROM", "ALERT_TO",
    "API_HOST", "API_PORT", "API_DEBUG",
    "LOG_LEVEL", "LOG_FORMAT", "LOG_FILE_ENABLED",
]


@pytest.fixture(autouse=True)
def _clean_env():
    """Save and restore env vars around every test to prevent contamination."""
    saved = {k: os.environ.pop(k, None) for k in _ENV_KEYS}
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


class TestSettingsDefaults:
    """Verify that Settings has sensible defaults when no env vars are set."""

    def test_settings_imports(self):
        """Settings class should be importable from src.config."""
        from src.config import Settings

        assert Settings is not None

    def test_settings_is_frozen(self):
        """Settings should be immutable (frozen dataclass)."""
        from src.config import Settings

        s = Settings()
        with pytest.raises(AttributeError):
            s.target_ip = "hacked"  # type: ignore[misc]

    def test_default_target_ip(self):
        from src.config import Settings

        s = Settings()
        assert s.target_ip == ""

    def test_default_ssh_port(self):
        from src.config import Settings

        s = Settings()
        assert s.ssh_port == 22

    def test_default_brute_force_threshold(self):
        from src.config import Settings

        s = Settings()
        assert s.brute_force_threshold == 5

    def test_default_api_port(self):
        from src.config import Settings

        s = Settings()
        assert s.api_port == 8000

    def test_default_data_dir(self):
        from src.config import Settings

        s = Settings()
        assert s.data_dir.name == "data"

    def test_default_log_level(self):
        from src.config import Settings

        s = Settings()
        assert s.log_level == "INFO"

    def test_default_log_format(self):
        from src.config import Settings

        s = Settings()
        assert s.log_format == "json"


class TestLoadSettings:
    """Verify that load_settings reads from env files correctly."""

    def test_loads_from_config_env(self):
        """load_settings should populate Settings from environment vars."""
        from src.config import load_settings

        # Set some env vars to simulate config.env
        env = {
            "TARGET_IP": "10.0.0.1",
            "SSH_USER": "admin",
            "ABUSEIPDB_API_KEY": "test_key_123",
            "TELEGRAM_BOT_TOKEN": "bot_token_abc",
            "TELEGRAM_CHAT_ID": "123456",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            for k, v in env.items():
                f.write(f"{k}={v}\n")
            f.flush()
            try:
                settings = load_settings(f.name)
                assert settings.target_ip == "10.0.0.1"
                assert settings.ssh_user == "admin"
                assert settings.abuseipdb_api_key == "test_key_123"
                assert settings.telegram_bot_token == "bot_token_abc"
                assert settings.telegram_chat_id == "123456"
            finally:
                os.unlink(f.name)

    def test_defaults_used_for_missing_vars(self):
        """Missing env vars should fall back to defaults."""
        from src.config import load_settings

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            # Only set target_ip, everything else should be defaults
            f.write("TARGET_IP=10.0.0.1\n")
            f.flush()
            try:
                settings = load_settings(f.name)
                assert settings.target_ip == "10.0.0.1"
                assert settings.ssh_port == 22
                assert settings.brute_force_threshold == 5
                assert settings.api_port == 8000
            finally:
                os.unlink(f.name)

    def test_integer_parsing(self):
        """Integer env vars should be parsed correctly."""
        from src.config import load_settings

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("SSH_PORT=2222\n")
            f.write("BRUTE_FORCE_THRESHOLD=10\n")
            f.write("API_PORT=9000\n")
            f.flush()
            try:
                settings = load_settings(f.name)
                assert settings.ssh_port == 2222
                assert settings.brute_force_threshold == 10
                assert settings.api_port == 9000
            finally:
                os.unlink(f.name)

    def test_float_parsing(self):
        """Float env vars should be parsed correctly."""
        from src.config import load_settings

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("ABUSEIPDB_MIN_SCORE=75.5\n")
            f.flush()
            try:
                settings = load_settings(f.name)
                assert settings.abuseipdb_min_score == 75.5
            finally:
                os.unlink(f.name)

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("true", True),
            ("false", False),
            ("1", True),
            ("0", False),
            ("yes", True),
            ("no", False),
            ("TRUE", True),
            ("False", False),
        ],
    )
    def test_boolean_parsing(self, value, expected):
        """Boolean env vars should accept true/false/1/0/yes/no."""
        from src.config import load_settings

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(f"AUTO_BAN_ENABLED={value}\n")
            f.flush()
            try:
                settings = load_settings(f.name)
                assert settings.auto_ban_enabled is expected, (
                    f"AUTO_BAN_ENABLED={value} should parse to {expected}"
                )
            finally:
                os.unlink(f.name)

    def test_invalid_integer_falls_back_to_default(self):
        """Non-numeric string for an int field should use the default."""
        from src.config import load_settings

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("SSH_PORT=not_a_number\n")
            f.flush()
            try:
                settings = load_settings(f.name)
                assert settings.ssh_port == 22  # default
            finally:
                os.unlink(f.name)

    def test_empty_file_uses_all_defaults(self):
        """An empty env file should produce all defaults."""
        from src.config import load_settings

        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("")
            f.flush()
            try:
                settings = load_settings(f.name)
                assert settings.target_ip == "192.168.56.20"
                assert settings.ssh_port == 22
                assert settings.api_port == 8000
                assert settings.log_level == "INFO"
            finally:
                os.unlink(f.name)


class TestSingleton:
    """Verify the module-level settings singleton works."""

    def test_singleton_exists(self):
        """Module-level settings should be pre-loaded."""
        from src.config import settings

        assert settings is not None
        assert hasattr(settings, "target_ip")

    def test_singleton_is_settings_instance(self):
        from src.config import Settings, settings

        assert isinstance(settings, Settings)
