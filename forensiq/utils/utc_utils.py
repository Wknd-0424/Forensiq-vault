"""
forensiq/utils/utc_utils.py
----------------------------
UTC-aware datetime helpers.
All application timestamps must use UTC and ISO-8601 format.
"""

from datetime import datetime, timezone


def now_utc() -> datetime:
    """Return the current moment as a timezone-aware UTC datetime."""
    return datetime.now(tz=timezone.utc)


_DEFAULT = object()


def to_iso8601(dt: Optional[datetime] = _DEFAULT) -> str:
    """
    Format a datetime as an ISO-8601 UTC string.
    Always includes the 'Z' suffix to be unambiguous.
    Example: '2026-09-05T14:32:01Z'
    - If called with no arguments, formats current UTC time.
    - If dt is None, returns an empty string.
    """
    if dt is _DEFAULT:
        dt = now_utc()
    if dt is None:
        return ""
    if dt.tzinfo is None:
        # Treat naive datetimes as UTC (should not happen in normal flow)
        dt = dt.replace(tzinfo=timezone.utc)
    utc = dt.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def from_iso8601(s: str) -> datetime:
    """
    Parse an ISO-8601 string to a timezone-aware UTC datetime.
    Accepts strings ending with 'Z' or '+00:00'.
    """
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def apply_offset(raw_dt: datetime, offset_seconds: float) -> datetime:
    """
    Apply a signed offset in seconds to a datetime to produce a
    normalized UTC timestamp.

    Convention:  normalized_utc = raw_dt + offset_seconds

    This is NOT a timezone conversion; it is an analyst-applied correction
    that must be documented and approved before use.
    """
    from datetime import timedelta
    return raw_dt + timedelta(seconds=offset_seconds)
