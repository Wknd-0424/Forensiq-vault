"""
forensiq/utils/security_utils.py
----------------------------------
Path traversal prevention and vault boundary enforcement.

Phase 2: Fully implemented.
"""

from pathlib import Path


class PathTraversalError(ValueError):
    """Raised when a resolved path falls outside the vault boundary."""


def is_within_vault(target: Path, vault_root: Path) -> bool:
    """
    Return True only if *target* resolves to a path inside *vault_root*.
    Both paths are resolved to absolute form before comparison.

    This is the primary path-traversal defence for all vault file operations.
    """
    try:
        target.resolve().relative_to(vault_root.resolve())
        return True
    except ValueError:
        return False


def assert_within_vault(target: Path, vault_root: Path) -> None:
    """
    Raise PathTraversalError if *target* is outside *vault_root*.
    Call this before any vault write operation.
    """
    if not is_within_vault(target, vault_root):
        raise PathTraversalError(
            f"Security violation: path '{target}' is outside vault root '{vault_root}'."
        )


def is_safe_extension(filename: str) -> bool:
    """Return True if the file's extension is in the allowed whitelist."""
    from forensiq.config import ALLOWED_EXTENSIONS
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def safe_vault_path(
    vault_root: Path,
    *parts: str,
) -> Path:
    """
    Construct and validate a vault-relative path.

    Joins *vault_root* with *parts*, resolves the result, and asserts
    it is still within *vault_root*.  Returns the resolved Path.

    This prevents any part containing '..' or absolute path segments
    from escaping the vault.
    """
    constructed = vault_root.joinpath(*parts)
    assert_within_vault(constructed, vault_root)
    return constructed.resolve()
