"""
mac_lookup.py - Resolve MAC addresses for hosts on the local network segment
using the OS ARP cache (works cross-platform without raw sockets).
"""

from __future__ import annotations

import platform
import re
import subprocess
from typing import Optional

from core.utils import setup_logging

logger = setup_logging(__name__)

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


def get_mac_from_arp_cache(ip: str) -> Optional[str]:
    """Look up a host's MAC address from the local OS ARP cache.

    This only works for hosts on the same local subnet, and typically
    requires the host to have been contacted recently (e.g. via ping)
    so the ARP cache is populated.

    Args:
        ip: IP address to look up.

    Returns:
        MAC address string (colon-separated, uppercase) if found, else None.
    """
    system = platform.system().lower()
    cmd = ["arp", "-a", ip] if system == "windows" else ["arp", "-n", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("ARP cache lookup failed for %s: %s", ip, exc)
        return None

    match = _MAC_RE.search(result.stdout)
    if match:
        return match.group(0).upper().replace("-", ":")
    return None
