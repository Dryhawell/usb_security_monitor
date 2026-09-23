"""Keep local JSON histories from growing without bound.

Oldest records are dropped. This is endpoint hygiene, not a SIEM archive
and not telemetry.
"""

from __future__ import annotations

from typing import Any, TypeVar

T = TypeVar("T")


def coerce_dropped_total(raw: Any) -> int:
    """Read a persisted drop counter. Invalid values become 0."""
    if not isinstance(raw, dict):
        return 0
    value = raw.get("dropped_total", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def keep_newest(items: list[T], max_records: int) -> tuple[list[T], int]:
    """Return the newest ``max_records`` items and how many were dropped.

    ``items`` is assumed append-ordered (oldest first).
    """
    if max_records < 1:
        raise ValueError("max_records must be >= 1")
    extra = len(items) - max_records
    if extra <= 0:
        return items, 0
    return items[extra:], extra
