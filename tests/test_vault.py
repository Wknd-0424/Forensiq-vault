"""
tests/test_vault.py
---------------------
Unit tests for forensiq.services.vault_service.

Uses tmp_path fixture for all vault operations — no actual VAULT_ROOT affected.

Phase 2: Fully implemented.
"""

import os
import stat
from pathlib import Path

import pytest

from forensiq.utils.hashing import hash_file
from forensiq.services.vault_service import (
    EvidencePaths,
    VaultError,
    copy_to_original,
    copy_to_working,
    create_evidence_dirs,
    set_read_only,
)
from forensiq.utils.security_utils import PathTraversalError, is_within_vault


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_evidence_file(tmp_path: Path, content: bytes = b"test video content") -> Path:
    p = tmp_path / "test_clip.mp4"
    p.write_bytes(content)
    return p


# ---------------------------------------------------------------------------
# TestCreateEvidenceDirs
# ---------------------------------------------------------------------------

class TestCreateEvidenceDirs:
    """Tests for vault directory creation."""

    def test_creates_all_required_dirs(self, tmp_path, monkeypatch):
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", tmp_path)
        
        paths = create_evidence_dirs("case-abc", "ev-123")
        assert paths.original_dir.exists()
        assert paths.working_copy_dir.exists()
        assert paths.derivatives_dir.exists()

    def test_paths_are_within_vault_root(self, tmp_path, monkeypatch):
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", tmp_path)
        paths = create_evidence_dirs("case-abc", "ev-123")
        assert is_within_vault(paths.original_dir, tmp_path)
        assert is_within_vault(paths.working_copy_dir, tmp_path)

    def test_idempotent_on_second_call(self, tmp_path, monkeypatch):
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", tmp_path)
        create_evidence_dirs("case-abc", "ev-123")
        # Second call should not raise
        create_evidence_dirs("case-abc", "ev-123")

    def test_manifest_path_is_set(self, tmp_path, monkeypatch):
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", tmp_path)
        paths = create_evidence_dirs("case-abc", "ev-123")
        assert paths.manifest_path.name == "manifest.json"


# ---------------------------------------------------------------------------
# TestCopyToOriginal
# ---------------------------------------------------------------------------

class TestCopyToOriginal:

    def _make_paths(self, tmp_path: Path, vault_root: Path) -> EvidencePaths:
        """Create EvidencePaths with directories inside vault_root."""
        base = vault_root / "case-1" / "evidence" / "ev-1"
        orig_dir = base / "original"
        wc_dir = base / "working_copy"
        der_dir = base / "derivatives"
        for d in (orig_dir, wc_dir, der_dir):
            d.mkdir(parents=True, exist_ok=True)
        return EvidencePaths(
            evidence_dir=base,
            original_dir=orig_dir,
            working_copy_dir=wc_dir,
            derivatives_dir=der_dir,
            manifest_path=base / "manifest.json",
        )

    def test_copy_creates_file_in_original_dir(self, tmp_path, monkeypatch):
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        src = _make_test_evidence_file(tmp_path)
        expected = hash_file(src).sha256
        paths = self._make_paths(tmp_path, vault)
        copy_to_original(src, paths, expected)
        assert paths.original_file is not None
        assert paths.original_file.exists()

    def test_copy_sets_original_file_on_paths(self, tmp_path, monkeypatch):
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        src = _make_test_evidence_file(tmp_path)
        expected = hash_file(src).sha256
        paths = self._make_paths(tmp_path, vault)
        copy_to_original(src, paths, expected)
        assert paths.original_file.name == src.name

    def test_copy_with_wrong_hash_raises_vault_error(self, tmp_path, monkeypatch):
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        src = _make_test_evidence_file(tmp_path)
        wrong_sha256 = "a" * 64
        paths = self._make_paths(tmp_path, vault)
        with pytest.raises(VaultError, match="mismatch"):
            copy_to_original(src, paths, wrong_sha256)

    def test_copy_with_wrong_hash_removes_bad_copy(self, tmp_path, monkeypatch):
        """After hash mismatch, no file should remain in original_dir."""
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        src = _make_test_evidence_file(tmp_path)
        wrong_sha256 = "a" * 64
        paths = self._make_paths(tmp_path, vault)
        with pytest.raises(VaultError):
            copy_to_original(src, paths, wrong_sha256)
        # original_dir should be empty
        assert list(paths.original_dir.iterdir()) == []

    def test_returns_hash_result(self, tmp_path, monkeypatch):
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        src = _make_test_evidence_file(tmp_path)
        expected = hash_file(src).sha256
        paths = self._make_paths(tmp_path, vault)
        result = copy_to_original(src, paths, expected)
        assert result.sha256 == expected


# ---------------------------------------------------------------------------
# TestSetReadOnly
# ---------------------------------------------------------------------------

class TestSetReadOnly:

    def test_set_read_only_returns_bool(self, tmp_path):
        p = tmp_path / "file.mp4"
        p.write_bytes(b"data")
        result = set_read_only(p)
        assert isinstance(result, bool)

    def test_set_read_only_does_not_raise(self, tmp_path):
        """Even if chmod fails (e.g., Windows), must not raise."""
        p = tmp_path / "file.mp4"
        p.write_bytes(b"data")
        # Should not raise regardless of success
        set_read_only(p)

    def test_nonexistent_file_returns_false(self, tmp_path):
        p = tmp_path / "nonexistent.mp4"
        result = set_read_only(p)
        assert result is False


# ---------------------------------------------------------------------------
# TestCopyToWorking
# ---------------------------------------------------------------------------

class TestCopyToWorking:

    def _full_paths(self, tmp_path: Path, vault: Path, content: bytes) -> tuple[EvidencePaths, str]:
        base = vault / "case-1" / "evidence" / "ev-1"
        orig_dir = base / "original"
        wc_dir = base / "working_copy"
        der_dir = base / "derivatives"
        for d in (orig_dir, wc_dir, der_dir):
            d.mkdir(parents=True, exist_ok=True)
        paths = EvidencePaths(
            evidence_dir=base,
            original_dir=orig_dir,
            working_copy_dir=wc_dir,
            derivatives_dir=der_dir,
            manifest_path=base / "manifest.json",
        )
        # Place file in original_dir
        orig_file = orig_dir / "test_clip.mp4"
        orig_file.write_bytes(content)
        paths.original_file = orig_file
        sha256 = hash_file(orig_file).sha256
        return paths, sha256

    def test_creates_working_copy(self, tmp_path, monkeypatch):
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        paths, sha256 = self._full_paths(tmp_path, vault, b"video content")
        copy_to_working(paths, sha256)
        assert paths.working_copy_file is not None
        assert paths.working_copy_file.exists()

    def test_working_copy_hash_matches_original(self, tmp_path, monkeypatch):
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        paths, sha256 = self._full_paths(tmp_path, vault, b"video content for wc")
        result = copy_to_working(paths, sha256)
        assert result.sha256 == sha256

    def test_raises_if_original_file_not_set(self, tmp_path, monkeypatch):
        vault = tmp_path / "vault"
        vault.mkdir()
        monkeypatch.setattr("forensiq.config.VAULT_ROOT", vault)
        base = vault / "case-x" / "evidence" / "ev-x"
        (base / "original").mkdir(parents=True)
        (base / "working_copy").mkdir(parents=True)
        (base / "derivatives").mkdir(parents=True)
        paths = EvidencePaths(
            evidence_dir=base,
            original_dir=base / "original",
            working_copy_dir=base / "working_copy",
            derivatives_dir=base / "derivatives",
            manifest_path=base / "manifest.json",
        )  # original_file is None
        with pytest.raises(VaultError, match="original_file"):
            copy_to_working(paths, "a" * 64)


# ---------------------------------------------------------------------------
# TestIsWithinVault
# ---------------------------------------------------------------------------

class TestIsWithinVault:

    def test_valid_path_inside_vault(self, tmp_path):
        vault = tmp_path / "vault"
        vault.mkdir()
        sub = vault / "case" / "ev" / "file.mp4"
        sub.parent.mkdir(parents=True)
        sub.write_bytes(b"x")
        assert is_within_vault(sub, vault) is True

    def test_traversal_outside_vault(self, tmp_path):
        vault = tmp_path / "vault"
        vault.mkdir()
        outside = tmp_path / "other_dir"
        outside.mkdir()
        assert is_within_vault(outside, vault) is False

    def test_double_dot_traversal(self, tmp_path):
        vault = tmp_path / "vault"
        vault.mkdir()
        bad = vault / ".." / "etc" / "passwd"
        assert is_within_vault(bad, vault) is False
