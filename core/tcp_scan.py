"""
tcp_scan.py - Asynchronous TCP connect scanning, with optional SYN scan via scapy.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import List, Optional

from core.utils import setup_logging

logger = setup_logging(__name__)

try:
    from scapy.all import IP, TCP, sr1  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


@dataclass
class PortResult:
    """Result of scanning a single TCP port."""

    port: int
    state: str  # 'open', 'closed', 'filtered'
    protocol: str = "tcp"


async def tcp_connect_scan_port(host: str, port: int, timeout: float = 1.5,
                                 retries: int = 1) -> PortResult:
    """Scan a single TCP port using a full connect() handshake.

    Args:
        host: Target IP address.
        port: TCP port number.
        timeout: Connection timeout in seconds.
        retries: Number of additional attempts on timeout.

    Returns:
        PortResult with state 'open', 'closed', or 'filtered'.
    """
    attempts = retries + 1
    for attempt in range(attempts):
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PortResult(port=port, state="open")
        except ConnectionRefusedError:
            return PortResult(port=port, state="closed")
        except asyncio.TimeoutError:
            if attempt == attempts - 1:
                return PortResult(port=port, state="filtered")
            continue
        except OSError:
            if attempt == attempts - 1:
                return PortResult(port=port, state="filtered")
            continue
    return PortResult(port=port, state="filtered")


async def tcp_connect_scan(host: str, ports: List[int], timeout: float = 1.5,
                            concurrency: int = 200, retries: int = 1) -> List[PortResult]:
    """Scan multiple TCP ports concurrently using connect scanning.

    Args:
        host: Target IP address.
        ports: List of ports to scan.
        timeout: Per-connection timeout.
        concurrency: Max concurrent connection attempts.
        retries: Retry attempts per port on timeout.

    Returns:
        List of PortResult objects, one per port scanned.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(port: int) -> PortResult:
        async with semaphore:
            return await tcp_connect_scan_port(host, port, timeout=timeout, retries=retries)

    tasks = [_bounded(p) for p in ports]
    return await asyncio.gather(*tasks)


def tcp_syn_scan_port(host: str, port: int, timeout: float = 1.5) -> PortResult:
    """Scan a single TCP port using a raw SYN packet (stealth scan).

    Requires scapy and elevated (root/admin) privileges to craft raw packets.
    Falls back to reporting 'filtered' if scapy/privileges are unavailable.

    Args:
        host: Target IP address.
        port: TCP port number.
        timeout: Response timeout in seconds.

    Returns:
        PortResult reflecting the SYN scan outcome.
    """
    if not _SCAPY_AVAILABLE:
        logger.warning("scapy not installed; cannot perform SYN scan on port %s.", port)
        return PortResult(port=port, state="filtered")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logger.warning("SYN scan requires root privileges; falling back to filtered state.")
        return PortResult(port=port, state="filtered")

    try:
        packet = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=False)
        if response is None:
            return PortResult(port=port, state="filtered")
        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            if flags == 0x12:  # SYN-ACK
                # Send RST to gracefully tear down the half-open connection
                rst = IP(dst=host) / TCP(dport=port, flags="R")
                sr1(rst, timeout=timeout, verbose=False)
                return PortResult(port=port, state="open")
            if flags == 0x14:  # RST-ACK
                return PortResult(port=port, state="closed")
        return PortResult(port=port, state="filtered")
    except PermissionError:
        logger.warning("Insufficient permissions for SYN scan on port %s.", port)
        return PortResult(port=port, state="filtered")
    except OSError as exc:
        logger.warning("SYN scan error on port %s: %s", port, exc)
        return PortResult(port=port, state="filtered")


def tcp_syn_scan(host: str, ports: List[int], timeout: float = 1.5) -> List[PortResult]:
    """Scan multiple ports using SYN scanning (sequential; raw sockets are not
    easily parallelized safely across asyncio without additional tooling).

    Args:
        host: Target IP address.
        ports: List of ports.
        timeout: Per-packet timeout.

    Returns:
        List of PortResult.
    """
    return [tcp_syn_scan_port(host, port, timeout=timeout) for port in ports]
