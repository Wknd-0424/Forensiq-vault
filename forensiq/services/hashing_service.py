"""
forensiq/services/hashing_service.py
--------------------------------------
Thin service wrapper around forensiq.utils.hashing.

Provides hash_file() and verify_file_hash() as the single call-site
for all hash operations in the application.  Logging is centralised here.

Phase 2: Fully implemented.
"""

import logging
from pathlib import Path
from typing import Callable, Optional

from forensiq.utils.hashing import HashResult, HashingError, hash_file, verify_file_hash

logger = logging.getLogger(__name__)

# Re-export so callers only need to import from hashing_service
__all__ = ["hash_file", "verify_file_hash", "HashResult", "HashingError"]
