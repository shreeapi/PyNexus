"""
hostname.py - Hostname and reverse DNS resolution helpers.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Optional

from core.utils import setup_logging

logger = setup_logging(__name__)


def _reverse_lookup_sync(ip: str) -> Optional[str]:
    """Synchronous reverse DNS lookup via socket.gethostbyaddr."""
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


async def get_reverse_dns(ip: str) -> Optional[str]:
    """Resolve the reverse DNS (PTR-style) hostname for an IP address.

    Args:
        ip: IP address string.

    Returns:
        Hostname string if resolvable, otherwise None.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _reverse_lookup_sync, ip)


def get_local_hostname() -> str:
    """Return the local machine's hostname."""
    return socket.gethostname()
