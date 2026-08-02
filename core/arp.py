"""
arp.py - ARP-based host discovery for local subnets (requires scapy + privileges).

Falls back gracefully (returns empty results with a warning) when scapy is not
installed or the process lacks permissions to send raw ARP frames.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from core.utils import setup_logging

logger = setup_logging(__name__)

try:
    from scapy.all import ARP, Ether, srp  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


@dataclass
class ArpResult:
    """Result of an ARP discovery probe."""

    ip: str
    mac: Optional[str] = None


def arp_scan(cidr: str, timeout: float = 2.0) -> List[ArpResult]:
    """Perform an ARP scan across a local subnet.

    Requires scapy to be installed and sufficient OS privileges (root/admin)
    to send raw Ethernet/ARP frames. If unavailable, returns an empty list.

    Args:
        cidr: CIDR notation subnet, e.g. "192.168.1.0/24".
        timeout: Time to wait for ARP replies, in seconds.

    Returns:
        List of ArpResult for hosts that replied.
    """
    if not _SCAPY_AVAILABLE:
        logger.warning(
            "scapy is not installed; ARP discovery is unavailable. "
            "Install with 'pip install scapy' and run with elevated privileges."
        )
        return []

    try:
        arp_request = ARP(pdst=cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _unanswered = srp(packet, timeout=timeout, verbose=False)
    except PermissionError:
        logger.warning("ARP scan requires elevated privileges (run as root/admin).")
        return []
    except OSError as exc:
        logger.warning("ARP scan failed: %s", exc)
        return []

    results: List[ArpResult] = []
    for _sent, received in answered:
        results.append(ArpResult(ip=received.psrc, mac=received.hwsrc))
    return results
