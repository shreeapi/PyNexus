"""
udp_scan.py - Asynchronous UDP port scanning.

UDP scanning is inherently ambiguous: a lack of response usually means
'open|filtered' since UDP is connectionless, while an ICMP port-unreachable
response indicates 'closed'.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import List

from core.utils import setup_logging

logger = setup_logging(__name__)

# Minimal protocol-specific probe payloads to elicit a response from common services
_UDP_PROBES = {
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",  # partial DNS query
    123: b"\x1b" + 47 * b"\x00",  # NTP request
    161: b"\x30\x26\x02\x01\x01\x04\x06public",  # partial SNMP
}


@dataclass
class UdpPortResult:
    """Result of scanning a single UDP port."""

    port: int
    state: str  # 'open', 'closed', 'open|filtered'
    protocol: str = "udp"


def _scan_udp_port_sync(host: str, port: int, timeout: float) -> UdpPortResult:
    """Synchronous helper performing a single UDP probe (run in executor)."""
    probe = _UDP_PROBES.get(port, b"\x00")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(probe, (host, port))
        try:
            data, _addr = sock.recvfrom(1024)
            state = "open" if data else "open|filtered"
        except socket.timeout:
            state = "open|filtered"
        except ConnectionResetError:
            # Windows raises this on ICMP port-unreachable
            state = "closed"
        return UdpPortResult(port=port, state=state)
    except OSError as exc:
        logger.debug("UDP scan error on port %s: %s", port, exc)
        return UdpPortResult(port=port, state="filtered")
    finally:
        sock.close()


async def udp_scan(host: str, ports: List[int], timeout: float = 1.5,
                    concurrency: int = 100) -> List[UdpPortResult]:
    """Scan multiple UDP ports concurrently.

    Args:
        host: Target IP address.
        ports: List of UDP ports.
        timeout: Timeout per probe in seconds.
        concurrency: Max concurrent probes.

    Returns:
        List of UdpPortResult objects.
    """
    semaphore = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()

    async def _bounded(port: int) -> UdpPortResult:
        async with semaphore:
            return await loop.run_in_executor(None, _scan_udp_port_sync, host, port, timeout)

    tasks = [_bounded(p) for p in ports]
    return await asyncio.gather(*tasks)
