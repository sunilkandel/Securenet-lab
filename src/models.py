"""
Core data models for SecureNet Lab.

Every component in the pipeline — collector, detector, threat_intel,
auto_ban, alerts, API — speaks the same language through these models.
The Event model is the central contract.

Usage:
    from src.models import Event, Severity, EventType

    event = Event(
        source_ip="192.168.56.10",
        event_type=EventType.SSH_BRUTE_FORCE,
        severity=Severity.HIGH,
        raw_log="Failed password for root from 192.168.56.10",
        mitre_technique="T1110",
        details={"attempts": 12, "user": "root"},
    )
    print(event.to_dict())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums — typed constants that keep the system self-documenting
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Attack severity levels, ordered low → critical."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """All recognised event types produced by detectors."""
    SSH_BRUTE_FORCE = "ssh_brute_force"
    PORT_SCAN = "port_scan"
    WEB_ENUMERATION = "web_enumeration"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    SQL_INJECTION = "sql_injection"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    AUTH_FAILURE = "auth_failure"
    SERVICE_PROBE = "service_probe"
    UNKNOWN = "unknown"


class AlertChannel(str, Enum):
    """Channels through which alerts are delivered."""
    TELEGRAM = "telegram"
    EMAIL = "email"


class AlertStatus(str, Enum):
    """Delivery status of an alert."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class BanStatus(str, Enum):
    """Whether a ban is currently active."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REMOVED = "removed"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _to_dict(obj: Any) -> dict[str, Any]:
    """Convert a dataclass (or Enum) to a plain dict recursively.

    Handles nested dataclasses, enums, and datetimes.
    """
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dataclass_fields__"):
        result = {}
        for fname in obj.__dataclass_fields__:  # type: ignore[attr-defined]
            val = getattr(obj, fname)
            result[fname] = _to_dict(val)
        return result
    if isinstance(obj, list):
        return [_to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def _from_dict(cls: type, data: dict[str, Any]) -> Any:
    """Reconstruct a dataclass instance from a plain dict.

    Handles nested dataclasses and enums by name.
    """
    if not hasattr(cls, "__dataclass_fields__"):
        return data

    kwargs = {}
    for fname, ftype in cls.__dataclass_fields__.items():  # type: ignore[attr-defined]
        if fname not in data:
            continue
        raw = data[fname]

        # Resolve the field's declared type
        field_type = ftype.type

        # Unwrap Optional / Union — just check inner types
        origin = getattr(field_type, "__origin__", None)
        if origin is not None:
            # Union[X, None] → args = (X, NoneType)
            args = getattr(field_type, "__args__", ())
            non_none = [a for a in args if a is not type(None)]
            if non_none:
                field_type = non_none[0]

        # Nested dataclass
        if hasattr(field_type, "__dataclass_fields__") and isinstance(raw, dict):
            kwargs[fname] = _from_dict(field_type, raw)
        # Enum
        elif isinstance(field_type, type) and issubclass(field_type, Enum):
            kwargs[fname] = field_type(raw) if isinstance(raw, str) else raw
        # list of dataclasses
        elif origin is list and raw is not None:
            inner_args = getattr(field_type, "__args__", [])
            if inner_args and hasattr(inner_args[0], "__dataclass_fields__") and isinstance(raw, list):
                kwargs[fname] = [_from_dict(inner_args[0], item) for item in raw]
            else:
                kwargs[fname] = raw
        else:
            kwargs[fname] = raw

    return cls(**kwargs)


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------

@dataclass
class Event:
    """A single security event detected by the pipeline.

    This is the central data structure — every component reads, writes,
    or reacts to Events. The `details` dict holds event-type-specific
    data (e.g., list of ports for port_scan, target paths for web_enum).
    """
    source_ip: str
    event_type: EventType
    severity: Severity
    raw_log: str = ""
    mitre_technique: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    # Populated by the system, not the detector
    id: int | None = None
    timestamp: str = field(default_factory=_utcnow)
    created_at: str = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for JSON / DB storage."""
        return _to_dict(self)

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        """Reconstruct an Event from a dict (e.g., from DB or JSON)."""
        return _from_dict(cls, data)  # type: ignore[return-value]

    @classmethod
    def from_json(cls, raw: str) -> Event:
        """Reconstruct an Event from a JSON string."""
        return cls.from_dict(json.loads(raw))


@dataclass
class IPInfo:
    """Metadata tracked for each observed IP address."""
    ip: str
    first_seen: str = field(default_factory=_utcnow)
    last_seen: str = field(default_factory=_utcnow)
    event_count: int = 0
    risk_score: float = 0.0          # 0.0 – 100.0

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IPInfo:
        return _from_dict(cls, data)  # type: ignore[return-value]


@dataclass
class Ban:
    """A firewall ban record."""
    ip: str
    reason: str = ""
    banned_at: str = field(default_factory=_utcnow)
    expires_at: str = ""             # empty = permanent
    status: BanStatus = BanStatus.ACTIVE
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Ban:
        return _from_dict(cls, data)  # type: ignore[return-value]


@dataclass
class ThreatIntel:
    """Result of an AbuseIPDB (or similar) lookup for a single IP."""
    ip: str
    abuse_confidence_score: float = 0.0
    country: str = ""
    isp: str = ""
    usage_type: str = ""
    lookup_result: dict[str, Any] = field(default_factory=dict)  # raw API response
    last_checked: str = field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatIntel:
        return _from_dict(cls, data)  # type: ignore[return-value]


@dataclass
class Alert:
    """Record of an alert sent (or attempted) via a channel."""
    event_id: int
    channel: AlertChannel
    status: AlertStatus = AlertStatus.PENDING
    sent_at: str = ""
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        return _from_dict(cls, data)  # type: ignore[return-value]
