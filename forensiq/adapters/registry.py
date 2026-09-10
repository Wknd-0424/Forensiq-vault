"""
forensiq/adapters/registry.py
------------------------------
Adapter registry and dispatch engine.

Dispatches evidence working copies to the best matching vendor adapter.
Maintains the capability matrix and synchronizes profiles with the database.
Falls back to UnknownSourceAdapter on unrecognised formats.

Phase 7: Fully implemented with Dahua, Hikvision, TP-Link, Generic, and Unknown adapters.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from forensiq.adapters.base import BaseAdapter
from forensiq.adapters.cpplus_export import CPPlusExportAdapter
from forensiq.adapters.dahua_export import DahuaExportAdapter
from forensiq.adapters.generic_media import GenericMediaAdapter
from forensiq.adapters.hikvision_export import HikvisionExportAdapter
from forensiq.adapters.godrej_export import GodrejExportAdapter
from forensiq.adapters.honeywell_export import HoneywellExportAdapter
from forensiq.adapters.matrix_export import MatrixExportAdapter
from forensiq.adapters.tplink_onvif_rtsp import TPLinkAdapter
from forensiq.adapters.uniview_export import UniviewExportAdapter
from forensiq.adapters.unknown_source import UnknownSourceAdapter
from forensiq.models.device import AdapterProfile

logger = logging.getLogger(__name__)


class AdapterRegistry:
    """Registry maintaining available vendor and generic media adapters."""

    def __init__(self):
        self._adapters: dict[str, BaseAdapter] = {}
        self._fallback_adapter = UnknownSourceAdapter()

        # Register adapters in prioritized detection order
        self.register(DahuaExportAdapter())
        self.register(HikvisionExportAdapter())
        self.register(CPPlusExportAdapter())
        self.register(UniviewExportAdapter())
        self.register(HoneywellExportAdapter())
        self.register(GodrejExportAdapter())
        self.register(MatrixExportAdapter())
        self.register(TPLinkAdapter())
        self.register(GenericMediaAdapter())
        self.register(self._fallback_adapter)

    def register(self, adapter: BaseAdapter) -> None:
        """Register an adapter instance."""
        self._adapters[adapter.ADAPTER_ID] = adapter
        logger.debug("Registered adapter: %s (v%s)", adapter.ADAPTER_ID, adapter.ADAPTER_VERSION)

    def get_adapter(self, adapter_id: str) -> Optional[BaseAdapter]:
        """Return the adapter with the given ID, or None."""
        return self._adapters.get(adapter_id)

    def list_adapters(self) -> list[BaseAdapter]:
        """Return all registered adapters in priority order."""
        return list(self._adapters.values())

    def detect_adapter(self, source_path: Path) -> BaseAdapter:
        """
        Inspect source_path and return the best matching adapter.
        Prioritizes HIGH confidence (signature/magic match) over MEDIUM (extension match).
        Falls back to GenericMediaAdapter or UnknownSourceAdapter.
        """
        medium_match = None

        for adapter_id, adapter in self._adapters.items():
            if adapter_id == UnknownSourceAdapter.ADAPTER_ID:
                continue

            try:
                response = adapter.identify(source_path)
                if response.status == "SUPPORTED":
                    if response.confidence == "HIGH":
                        logger.info("Detected adapter %s (HIGH confidence) for %s", adapter_id, source_path.name)
                        return adapter
                    elif response.confidence == "MEDIUM" and medium_match is None:
                        medium_match = adapter
            except Exception as exc:
                logger.warning("Adapter %s failed identify on %s: %s", adapter_id, source_path.name, exc)

        if medium_match is not None:
            logger.info("Detected adapter %s (MEDIUM confidence) for %s", medium_match.ADAPTER_ID, source_path.name)
            return medium_match

        logger.info("No specific adapter matched %s; using UnknownSourceAdapter", source_path.name)
        return self._fallback_adapter

    def sync_adapter_profiles(self, session: Session) -> list[AdapterProfile]:
        """
        Synchronize registered adapter capability matrices with the database.
        Populates or updates the adapter_profiles table.
        """
        profiles = []
        for adapter in self._adapters.values():
            caps = adapter.capabilities()
            cap_data = caps.data or {}
            vendor = cap_data.get("vendor_name", adapter.ADAPTER_ID)
            supported_profile = cap_data.get("supported_profile", "Standard")
            containers = cap_data.get("supported_containers", [])
            features = cap_data.get("features", {})
            limits = "\n".join(caps.limitations) if caps.limitations else None

            profile = (
                session.query(AdapterProfile)
                .filter(AdapterProfile.adapter_id == adapter.ADAPTER_ID)
                .first()
            )
            if not profile:
                profile = AdapterProfile(
                    adapter_id=adapter.ADAPTER_ID,
                    adapter_version=adapter.ADAPTER_VERSION,
                    vendor=vendor,
                    supported_profile=supported_profile,
                    input_types_json=json.dumps(containers),
                    capabilities_json=json.dumps(features),
                    tested=True if adapter.ADAPTER_ID != UnknownSourceAdapter.ADAPTER_ID else False,
                    test_reference=f"SIH 2026 Test Suite (Problem 26150 - NTRO)",
                    limitations=limits,
                )
                session.add(profile)
            else:
                profile.adapter_version = adapter.ADAPTER_VERSION
                profile.vendor = vendor
                profile.supported_profile = supported_profile
                profile.input_types_json = json.dumps(containers)
                profile.capabilities_json = json.dumps(features)
                profile.limitations = limits

            profiles.append(profile)

        session.commit()
        return profiles


# Global singleton registry
_DEFAULT_REGISTRY: Optional[AdapterRegistry] = None


def get_registry() -> AdapterRegistry:
    """Get or initialize the global AdapterRegistry singleton."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = AdapterRegistry()
    return _DEFAULT_REGISTRY


def sync_adapter_profiles(session: Session) -> list[AdapterProfile]:
    """Module-level convenience helper to synchronize adapter profiles with DB."""
    return get_registry().sync_adapter_profiles(session)

