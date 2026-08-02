"""
vendor.py - MAC address vendor (OUI) lookup, backed by database/vendors.json.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict, Optional

from config import VENDORS_DB_PATH
from core.utils import setup_logging

logger = setup_logging(__name__)


@lru_cache(maxsize=1)
def _load_vendor_db() -> Dict[str, str]:
    """Load the OUI vendor database from disk."""
    db: Dict[str, str] = {}
    if os.path.exists(VENDORS_DB_PATH):
        try:
            with open(VENDORS_DB_PATH, "r", encoding="utf-8") as fh:
                db = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load vendors.json (%s).", exc)
    return db


def lookup_vendor(mac_address: str) -> Optional[str]:
    """Look up the vendor name for a MAC address using its OUI prefix.

    Args:
        mac_address: MAC address string, e.g. "AA:BB:CC:11:22:33".

    Returns:
        Vendor name if known, otherwise None.
    """
    if not mac_address:
        return None
    normalized = mac_address.upper().replace("-", ":")
    prefix = ":".join(normalized.split(":")[:3])
    db = _load_vendor_db()
    return db.get(prefix)
