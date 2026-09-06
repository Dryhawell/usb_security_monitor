"""UTC timestamp helpers.

Internal timestamps are timezone-aware UTC. Display helpers produce a
human-readable string; storage uses ISO-8601 with a ``Z`` suffix.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current UTC time as an aware datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC; convert aware datetimes to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_iso8601(value: datetime) -> str:
    """Serialize a datetime to UTC ISO-8601 with millisecond precision."""
    utc_value = ensure_utc(value)
    return utc_value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def from_iso8601(value: str | datetime) -> datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""
    if isinstance(value, datetime):
        return ensure_utc(value)

    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    return ensure_utc(parsed)


def format_display(value: datetime) -> str:
    """Return a human-readable UTC timestamp, for example ``2026-09-04 14:31:22 UTC``."""
    return ensure_utc(value).strftime("%Y-%m-%d %H:%M:%S UTC")
