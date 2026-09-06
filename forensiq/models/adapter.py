"""
forensiq/models/adapter.py
---------------------------
Adapter-related model stub.

AdapterProfile is defined in device.py (same logical group).
This module re-exports it for convenience and holds any future
adapter-specific models.

Phase 1: Re-export only.
"""

from forensiq.models.device import AdapterProfile  # noqa: F401

__all__ = ["AdapterProfile"]
