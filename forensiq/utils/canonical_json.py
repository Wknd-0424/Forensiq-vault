"""
forensiq/utils/canonical_json.py
----------------------------------
Produces a deterministic, UTF-8, sorted-key JSON serialisation for
SHA-256 hashing of chain-of-custody events.

Rules:
- Keys sorted alphabetically.
- No unnecessary whitespace (compact separators).
- UTF-8 encoding.
- datetime objects serialised to ISO-8601 UTC strings.
- None serialised as JSON null.
"""

import json
from datetime import datetime

from forensiq.utils.utc_utils import to_iso8601


class _ForensicEncoder(json.JSONEncoder):
    """Custom encoder that handles datetime → ISO-8601 UTC string."""

    def default(self, obj):
        if isinstance(obj, datetime):
            return to_iso8601(obj)
        return super().default(obj)


def canonical_dumps(data: dict) -> str:
    """
    Serialise *data* to a canonical UTF-8 JSON string suitable for hashing.

    Returns a str (not bytes).  Callers should encode to UTF-8 before
    passing to hashlib.
    """
    return json.dumps(
        data,
        cls=_ForensicEncoder,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_bytes(data: dict) -> bytes:
    """Return the canonical JSON as UTF-8 bytes for direct use with hashlib."""
    return canonical_dumps(data).encode("utf-8")
