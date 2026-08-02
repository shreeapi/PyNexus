"""
services.py - Service name lookup by port/protocol, backed by database/services.json.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict

from config import DEFAULT_SERVICE_MAP, SERVICES_DB_PATH
from core.utils import setup_logging

logger = setup_logging(__name__)


@lru_cache(maxsize=1)
def _load_service_db() -> Dict[str, str]:
    """Load the services database from disk, falling back to defaults."""
    db: Dict[str, str] = {str(k): v for k, v in DEFAULT_SERVICE_MAP.items()}
    if os.path.exists(SERVICES_DB_PATH):
        try:
            with open(SERVICES_DB_PATH, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            db.update({str(k): v for k, v in loaded.items()})
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load services.json (%s); using defaults.", exc)
    return db


def lookup_service(port: int, protocol: str = "tcp") -> str:
    """Look up the conventional service name for a given port.

    Args:
        port: Port number.
        protocol: 'tcp' or 'udp' (currently informational only).

    Returns:
        Service name string, or 'unknown' if not found.
    """
    db = _load_service_db()
    return db.get(str(port), "unknown")
