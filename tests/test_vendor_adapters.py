"""
tests/test_vendor_adapters.py
-----------------------------
Unit and integration tests for proprietary DVR/NVR vendor adapters:
  - DahuaExportAdapter (DHAV, DAHUA, DHFS, .dav)
  - HikvisionExportAdapter (HIKVISION, HKAA, HKBB, .hkv)
  - TPLinkAdapter (VIGI, Tapo, ONVIF)
  - AdapterRegistry dispatch, prioritization, and profile synchronization

Phase 7: Fully implemented.
"""

from pathlib import Path

import pytest

from forensiq.adapters.cpplus_export import CPPlusExportAdapter
from forensiq.adapters.dahua_export import DahuaExportAdapter
from forensiq.adapters.hikvision_export import HikvisionExportAdapter
from forensiq.adapters.honeywell_export import HoneywellExportAdapter
from forensiq.adapters.registry import AdapterRegistry, get_registry
from forensiq.adapters.tplink_onvif_rtsp import TPLinkAdapter
from forensiq.adapters.uniview_export import UniviewExportAdapter
from forensiq.adapters.unknown_source import UnknownSourceAdapter
from forensiq.database import init_db, session_scope
from forensiq.models.device import AdapterProfile


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Redirect DB to isolated test database."""
    db_url = f"sqlite:///{tmp_path / 'test_adapters.db'}"
    monkeypatch.setattr("forensiq.config.DB_URL", db_url)
    monkeypatch.setattr("forensiq.database.DB_URL", db_url)

    import forensiq.database as db_mod
    db_mod._engine = None
    db_mod._SessionLocal = None

    init_db()
    yield

    db_mod._engine = None
    db_mod._SessionLocal = None


class TestDahuaExportAdapter:
    """Test suite for Dahua Technology surveillance export adapter."""

    def test_identify_by_magic_bytes(self, tmp_path):
        adapter = DahuaExportAdapter()

        # Create file with DHAV magic
        dhav_file = tmp_path / "stream.bin"
        dhav_file.write_bytes(b"\x00\x00\x00\x00DHAV\x01\x02\x03\x04video_payload")

        resp = adapter.identify(dhav_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "DHAV" in resp.basis
        assert resp.data["vendor"] == "Dahua Technology"

    def test_identify_by_dahua_header(self, tmp_path):
        adapter = DahuaExportAdapter()

        dahua_file = tmp_path / "export.raw"
        dahua_file.write_bytes(b"DAHUA_SURVEILLANCE_HEADER\x00\x01\x02")

        resp = adapter.identify(dahua_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "DAHUA" in resp.basis

    def test_identify_by_dav_extension(self, tmp_path):
        adapter = DahuaExportAdapter()

        dav_file = tmp_path / "ch01_20260301.dav"
        dav_file.write_bytes(b"\x01\x02\x03\x04generic_content")

        resp = adapter.identify(dav_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "MEDIUM"
        assert ".dav" in resp.basis

    def test_identify_unsupported_file(self, tmp_path):
        adapter = DahuaExportAdapter()

        other_file = tmp_path / "notes.txt"
        other_file.write_text("Case notes", encoding="utf-8")

        resp = adapter.identify(other_file)
        assert resp.status == "UNSUPPORTED"
        assert resp.confidence == "NONE"

    def test_capabilities_matrix(self):
        adapter = DahuaExportAdapter()
        caps = adapter.capabilities()

        assert caps.status == "SUPPORTED"
        assert caps.data["vendor_name"] == "Dahua Technology"
        assert "dhav_packet_parsing" in caps.data["features"]
        assert len(caps.limitations) > 0


class TestHikvisionExportAdapter:
    """Test suite for Hikvision Digital Technology surveillance export adapter."""

    def test_identify_by_hikvision_magic(self, tmp_path):
        adapter = HikvisionExportAdapter()

        hik_file = tmp_path / "camera_feed.bin"
        hik_file.write_bytes(b"\x00\x00HIKVISION\x01\x02\x03packet_data")

        resp = adapter.identify(hik_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "HIKVISION" in resp.basis
        assert resp.data["vendor"] == "Hikvision Digital Technology"

    def test_identify_by_hkaa_header(self, tmp_path):
        adapter = HikvisionExportAdapter()

        hkaa_file = tmp_path / "feed.264"
        hkaa_file.write_bytes(b"HKAA\x00\x01\x02\x03")

        resp = adapter.identify(hkaa_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "HKAA" in resp.basis

    def test_identify_by_hkv_extension(self, tmp_path):
        adapter = HikvisionExportAdapter()

        hkv_file = tmp_path / "hallway_camera.hkv"
        hkv_file.write_bytes(b"\x00\x00\x00\x00raw_stream")

        resp = adapter.identify(hkv_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert ".hkv" in resp.basis

    def test_capabilities_matrix(self):
        adapter = HikvisionExportAdapter()
        caps = adapter.capabilities()

        assert caps.status == "SUPPORTED"
        assert caps.data["vendor_name"] == "Hikvision Digital Technology"
        assert "hik_packet_parsing" in caps.data["features"]
        assert len(caps.limitations) > 0


class TestTPLinkAdapter:
    """Test suite for TP-Link (VIGI/Tapo) and ONVIF surveillance export adapter."""

    def test_identify_by_filename_keyword(self, tmp_path):
        adapter = TPLinkAdapter()

        vigi_file = tmp_path / "VIGI_C340_20260301.mp4"
        vigi_file.write_bytes(b"\x00\x00\x00\x20ftypmp42")

        resp = adapter.identify(vigi_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "MEDIUM"
        assert "vigi" in resp.basis.lower()

    def test_identify_by_onvif_header_signature(self, tmp_path):
        adapter = TPLinkAdapter()

        onvif_file = tmp_path / "export.mp4"
        onvif_file.write_bytes(b"\x00\x00\x00\x20ftypmp42...onvif profile-s export data")

        resp = adapter.identify(onvif_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "onvif" in resp.basis.lower()

    def test_unsupported_extension(self, tmp_path):
        adapter = TPLinkAdapter()

        txt_file = tmp_path / "vigi_notes.txt"
        txt_file.write_text("vigi camera notes", encoding="utf-8")

        resp = adapter.identify(txt_file)
        assert resp.status == "UNSUPPORTED"


class TestCPPlusExportAdapter:
    """Test suite for CP Plus (Aditya Infotech) surveillance export adapter."""

    def test_identify_by_cpplus_magic(self, tmp_path):
        adapter = CPPlusExportAdapter()
        cpplus_file = tmp_path / "feed.bin"
        cpplus_file.write_bytes(b"\x00\x00CPPLUS\x01\x02\x03stream_payload")

        resp = adapter.identify(cpplus_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "CPPLUS" in resp.basis
        assert resp.data["vendor"] == "CP Plus (Aditya Infotech)"

    def test_identify_by_cppl_sync_tag(self, tmp_path):
        adapter = CPPlusExportAdapter()
        cppl_file = tmp_path / "camera4.264"
        cppl_file.write_bytes(b"CPPL\x00\x04\x00\x00")

        resp = adapter.identify(cppl_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "CPPL" in resp.basis

    def test_identify_by_cvr_extension(self, tmp_path):
        adapter = CPPlusExportAdapter()
        cvr_file = tmp_path / "backup_archive.cvr"
        cvr_file.write_bytes(b"\x00\x00\x00\x00raw_stream")

        resp = adapter.identify(cvr_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "MEDIUM"
        assert ".cvr" in resp.basis

    def test_capabilities_matrix(self):
        adapter = CPPlusExportAdapter()
        caps = adapter.capabilities()
        assert caps.status == "SUPPORTED"
        assert caps.data["vendor_name"] == "CP Plus (Aditya Infotech)"
        assert "cpplus_packet_parsing" in caps.data["features"]
        assert len(caps.limitations) > 0


class TestUniviewExportAdapter:
    """Test suite for Uniview Technologies (UNV) surveillance export adapter."""

    def test_identify_by_ubvr_magic(self, tmp_path):
        adapter = UniviewExportAdapter()
        ubvr_file = tmp_path / "unv_stream.bin"
        ubvr_file.write_bytes(b"UBVR\x00\x01\x00\x01payload")

        resp = adapter.identify(ubvr_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "UBVR" in resp.basis
        assert resp.data["vendor"] == "Uniview Technologies (UNV)"

    def test_identify_by_unvrec_header(self, tmp_path):
        adapter = UniviewExportAdapter()
        unv_file = tmp_path / "server_room.dat"
        unv_file.write_bytes(b"\x00\x00UNVREC\x05\x00")

        resp = adapter.identify(unv_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "UNVREC" in resp.basis

    def test_identify_by_uvf_extension(self, tmp_path):
        adapter = UniviewExportAdapter()
        uvf_file = tmp_path / "cam05.uvf"
        uvf_file.write_bytes(b"\x00\x00\x00\x00")

        resp = adapter.identify(uvf_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "MEDIUM"
        assert ".uvf" in resp.basis

    def test_capabilities_matrix(self):
        adapter = UniviewExportAdapter()
        caps = adapter.capabilities()
        assert caps.status == "SUPPORTED"
        assert caps.data["vendor_name"] == "Uniview Technologies (UNV)"
        assert "ubvr_packet_parsing" in caps.data["features"]
        assert len(caps.limitations) > 0


class TestHoneywellExportAdapter:
    """Test suite for Honeywell Security surveillance export adapter."""

    def test_identify_by_honeywell_magic(self, tmp_path):
        adapter = HoneywellExportAdapter()
        hos_file = tmp_path / "hq_gate.bin"
        hos_file.write_bytes(b"HONEYWELL\x00\x01clip_data")

        resp = adapter.identify(hos_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "HONEYWELL" in resp.basis
        assert resp.data["vendor"] == "Honeywell Security"

    def test_identify_by_hos_sync_tag(self, tmp_path):
        adapter = HoneywellExportAdapter()
        hos_file = tmp_path / "feed.264"
        hos_file.write_bytes(b"HOS\x01\x00\x01")

        resp = adapter.identify(hos_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "HIGH"
        assert "HOS" in resp.basis

    def test_identify_by_hos_extension(self, tmp_path):
        adapter = HoneywellExportAdapter()
        hos_file = tmp_path / "gate.hos"
        hos_file.write_bytes(b"\x00\x00\x00\x00")

        resp = adapter.identify(hos_file)
        assert resp.status == "SUPPORTED"
        assert resp.confidence == "MEDIUM"
        assert ".hos" in resp.basis

    def test_capabilities_matrix(self):
        adapter = HoneywellExportAdapter()
        caps = adapter.capabilities()
        assert caps.status == "SUPPORTED"
        assert caps.data["vendor_name"] == "Honeywell Security"
        assert "hos_packet_parsing" in caps.data["features"]
        assert len(caps.limitations) > 0


class TestAdapterRegistryIntegration:
    """Integration test suite for AdapterRegistry dispatch and profile sync."""

    def test_registry_contains_all_vendor_adapters(self):
        registry = AdapterRegistry()
        adapters = registry.list_adapters()

        adapter_ids = [a.ADAPTER_ID for a in adapters]
        assert "dahua_export" in adapter_ids
        assert "hikvision_export" in adapter_ids
        assert "cpplus_export" in adapter_ids
        assert "uniview_export" in adapter_ids
        assert "honeywell_export" in adapter_ids
        assert "tplink_onvif" in adapter_ids
        assert "generic_media" in adapter_ids
        assert "unknown_source" in adapter_ids

    def test_detection_prioritizes_dahua_over_generic(self, tmp_path):
        registry = AdapterRegistry()
        dav_file = tmp_path / "evidence.dav"
        dav_file.write_bytes(b"DHAV\x00\x01\x02\x03")

        detected = registry.detect_adapter(dav_file)
        assert detected.ADAPTER_ID == "dahua_export"

    def test_detection_prioritizes_hikvision_over_generic(self, tmp_path):
        registry = AdapterRegistry()
        hik_mp4 = tmp_path / "evidence.mp4"
        hik_mp4.write_bytes(b"\x00\x00\x00\x20HIKVISION\x00\x01\x02")

        detected = registry.detect_adapter(hik_mp4)
        assert detected.ADAPTER_ID == "hikvision_export"

    def test_detection_prioritizes_cpplus_over_generic(self, tmp_path):
        registry = AdapterRegistry()
        cp_file = tmp_path / "perimeter.dav"
        cp_file.write_bytes(b"CPPLUS\x04\x00")

        detected = registry.detect_adapter(cp_file)
        assert detected.ADAPTER_ID == "cpplus_export"

    def test_detection_prioritizes_uniview_over_generic(self, tmp_path):
        registry = AdapterRegistry()
        unv_file = tmp_path / "server.uvf"
        unv_file.write_bytes(b"UBVR\x00\x01")

        detected = registry.detect_adapter(unv_file)
        assert detected.ADAPTER_ID == "uniview_export"

    def test_detection_prioritizes_honeywell_over_generic(self, tmp_path):
        registry = AdapterRegistry()
        hos_file = tmp_path / "gate.hos"
        hos_file.write_bytes(b"HONEYWELL\x00\x01")

        detected = registry.detect_adapter(hos_file)
        assert detected.ADAPTER_ID == "honeywell_export"

    def test_detection_falls_back_to_generic_for_standard_mp4(self, tmp_path):
        registry = AdapterRegistry()

        std_mp4 = tmp_path / "standard.mp4"
        std_mp4.write_bytes(b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00")

        detected = registry.detect_adapter(std_mp4)
        assert detected.ADAPTER_ID == "generic_media"

    def test_detection_falls_back_to_unknown_source_on_arbitrary_binary(self, tmp_path):
        registry = AdapterRegistry()

        bin_file = tmp_path / "corrupt_data.xyz"
        bin_file.write_bytes(b"\xff\xfe\xfd\xfc\x00\x11\x22\x33")

        detected = registry.detect_adapter(bin_file)
        assert detected.ADAPTER_ID == "unknown_source"

    def test_sync_adapter_profiles_persists_to_db(self):
        registry = AdapterRegistry()

        with session_scope() as session:
            profiles = registry.sync_adapter_profiles(session)
            assert len(profiles) >= 8

            stored = session.query(AdapterProfile).all()
            assert len(stored) >= 8
            stored_ids = {p.adapter_id for p in stored}
            assert "dahua_export" in stored_ids
            assert "hikvision_export" in stored_ids
            assert "cpplus_export" in stored_ids
            assert "uniview_export" in stored_ids
            assert "honeywell_export" in stored_ids
            assert "tplink_onvif" in stored_ids
            assert "generic_media" in stored_ids
