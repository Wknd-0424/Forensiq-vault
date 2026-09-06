"""
tests/test_hashing.py
----------------------
Unit tests for forensiq.utils.hashing.

All tests use synthetic in-memory or temp-file data.
No real video footage is required.

Phase 2: Fully implemented.
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from forensiq.utils.hashing import HashResult, HashingError, hash_file, verify_file_hash


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_file_1mb(tmp_path):
    """Create a 1 MB temp file with pseudo-random (deterministic) content."""
    p = tmp_path / "test_evidence.mp4"
    # Deterministic content: 1 MB of bytes derived from a fixed seed
    content = bytes(range(256)) * (1024 * 1024 // 256)
    p.write_bytes(content)
    return p


@pytest.fixture
def temp_file_small(tmp_path):
    """Create a small (13-byte) temp file with known content."""
    p = tmp_path / "small.mp4"
    p.write_bytes(b"hello forensiq")  # 14 bytes
    return p


@pytest.fixture
def temp_empty_file(tmp_path):
    """Create an empty (0-byte) temp file."""
    p = tmp_path / "empty.mp4"
    p.write_bytes(b"")
    return p


# ---------------------------------------------------------------------------
# TestHashResult
# ---------------------------------------------------------------------------

class TestHashFile:

    def test_returns_hash_result_type(self, temp_file_small):
        result = hash_file(temp_file_small)
        assert isinstance(result, HashResult)

    def test_sha256_is_64_hex_chars(self, temp_file_small):
        result = hash_file(temp_file_small)
        assert len(result.sha256) == 64
        assert all(c in "0123456789abcdef" for c in result.sha256)

    def test_md5_is_32_hex_chars(self, temp_file_small):
        result = hash_file(temp_file_small)
        assert len(result.md5) == 32
        assert all(c in "0123456789abcdef" for c in result.md5)

    def test_sha256_matches_known_value(self, temp_file_small):
        expected_sha256 = hashlib.sha256(b"hello forensiq").hexdigest()
        result = hash_file(temp_file_small)
        assert result.sha256 == expected_sha256

    def test_md5_matches_known_value(self, temp_file_small):
        expected_md5 = hashlib.md5(b"hello forensiq").hexdigest()
        result = hash_file(temp_file_small)
        assert result.md5 == expected_md5

    def test_size_bytes_is_correct(self, temp_file_small):
        result = hash_file(temp_file_small)
        assert result.size_bytes == 14  # len(b"hello forensiq")

    def test_result_is_frozen(self, temp_file_small):
        result = hash_file(temp_file_small)
        with pytest.raises((AttributeError, TypeError)):
            result.sha256 = "bad"  # type: ignore[misc]

    def test_large_file_hashes_correctly(self, temp_file_1mb):
        result = hash_file(temp_file_1mb)
        assert len(result.sha256) == 64
        assert result.size_bytes == 1024 * 1024

    def test_progress_callback_called(self, temp_file_1mb):
        calls = []
        def cb(done, total):
            calls.append((done, total))
        hash_file(temp_file_1mb, progress_cb=cb)
        assert len(calls) >= 1
        # Last call should have done == total
        last_done, last_total = calls[-1]
        assert last_done == last_total

    def test_progress_total_equals_file_size(self, temp_file_1mb):
        totals = set()
        def cb(done, total):
            totals.add(total)
        hash_file(temp_file_1mb, progress_cb=cb)
        assert temp_file_1mb.stat().st_size in totals

    def test_hashing_nonexistent_file_raises(self, tmp_path):
        with pytest.raises(HashingError):
            hash_file(tmp_path / "nonexistent.mp4")

    def test_hashing_empty_file_raises(self, temp_empty_file):
        with pytest.raises(HashingError, match="empty"):
            hash_file(temp_empty_file)

    def test_deterministic_same_content_same_hash(self, tmp_path):
        """Two files with identical content must produce identical hashes."""
        content = b"deterministic content " * 1000
        f1 = tmp_path / "a.mp4"
        f2 = tmp_path / "b.mp4"
        f1.write_bytes(content)
        f2.write_bytes(content)
        r1 = hash_file(f1)
        r2 = hash_file(f2)
        assert r1.sha256 == r2.sha256
        assert r1.md5 == r2.md5


# ---------------------------------------------------------------------------
# TestVerifyFileHash
# ---------------------------------------------------------------------------

class TestVerifyFileHash:

    def test_verify_correct_hash_returns_true(self, temp_file_small):
        result = hash_file(temp_file_small)
        assert verify_file_hash(temp_file_small, result.sha256) is True

    def test_verify_wrong_hash_returns_false(self, temp_file_small):
        wrong = "a" * 64
        assert verify_file_hash(temp_file_small, wrong) is False

    def test_verify_is_case_insensitive(self, temp_file_small):
        result = hash_file(temp_file_small)
        assert verify_file_hash(temp_file_small, result.sha256.upper()) is True

    def test_verify_modified_file_returns_false(self, tmp_path):
        p = tmp_path / "ev.mp4"
        p.write_bytes(b"original content")
        original_hash = hash_file(p)
        # Modify file
        p.write_bytes(b"tampered content")
        assert verify_file_hash(p, original_hash.sha256) is False

    def test_verify_nonexistent_file_raises(self, tmp_path):
        with pytest.raises(HashingError):
            verify_file_hash(tmp_path / "missing.mp4", "a" * 64)
