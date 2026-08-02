"""
discover.py - Fast LAN device discovery: sweeps a subnet and enriches each
live host with hostname, MAC address, and vendor information. This is the
engine behind the `discover` CLI subcommand ("who's on my network").
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import List, Optional

from core import arp as arp_mod
from core import hostname as hostname_mod
from core import mac_lookup as mac_mod
from core import vendor as vendor_mod
from core.ping import check_host_alive
from core.utils import setup_logging

logger = setup_logging(__name__)


@dataclass
class DeviceInfo:
    """A single discovered device on the local network."""

    ip: str
    alive: bool = True
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    latency_ms: Optional[float] = None
    discovery_method: Optional[str] = None
    is_self: bool = False


def get_local_ip() -> Optional[str]:
    """Best-effort detection of this machine's primary LAN IPv4 address.

    Uses a UDP "connect" (no packets are actually sent) to a public address
    purely to let the OS pick the outbound interface/IP.

    Returns:
        Local IPv4 address string, or None if it could not be determined.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def guess_local_cidr() -> Optional[str]:
    """Guess the local /24 subnet in CIDR notation based on this machine's IP.

    Returns:
        CIDR string like "192.168.1.0/24", or None if detection failed.
    """
    local_ip = get_local_ip()
    if not local_ip:
        return None
    octets = local_ip.split(".")
    if len(octets) != 4:
        return None
    return f"{'.'.join(octets[:3])}.0/24"


async def _enrich_device(ip: str, timeout: float, local_ip: Optional[str]) -> DeviceInfo:
    """Run liveness check + hostname/MAC/vendor enrichment for a single IP."""
    ping_result = await check_host_alive(ip, timeout=timeout)
    device = DeviceInfo(ip=ip, alive=ping_result.alive,
                         latency_ms=ping_result.latency_ms,
                         discovery_method=ping_result.method,
                         is_self=(ip == local_ip))
    if not device.alive:
        return device

    device.hostname = await hostname_mod.get_reverse_dns(ip)

    loop = asyncio.get_running_loop()
    device.mac_address = await loop.run_in_executor(None, mac_mod.get_mac_from_arp_cache, ip)
    if device.mac_address:
        device.vendor = vendor_mod.lookup_vendor(device.mac_address)
    return device


async def _arp_scan_async(cidr: str, timeout: float) -> List[arp_mod.ArpResult]:
    """Run the (blocking) scapy ARP scan in a thread executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, arp_mod.arp_scan, cidr, timeout)


async def discover_devices(hosts: List[str], timeout: float = 1.0,
                            concurrency: int = 150,
                            progress_callback=None,
                            cidr: Optional[str] = None) -> List[DeviceInfo]:
    """Discover devices on a subnet using ARP first (if available), then
    filling in gaps with an ICMP/TCP ping sweep.

    ARP requests are answered by every live IPv4 device on the local Ethernet
    segment regardless of firewall rules or ICMP being blocked, so it finds
    far more devices (phones in sleep mode, IoT gear, etc.) than ping alone.
    ARP requires `scapy` plus a packet-capture driver (Npcap on Windows,
    libpcap on Linux/macOS) and is typically only reliable when run with
    elevated privileges. If it's unavailable, this transparently falls back
    to the pure ping/TCP sweep.

    Args:
        hosts: List of candidate IP addresses (e.g. from a /24 expansion).
        timeout: Per-host liveness check timeout in seconds.
        concurrency: Max concurrent liveness checks.
        progress_callback: Optional callable(completed: int, total: int).
        cidr: Original CIDR string (e.g. "192.168.1.0/24"), used for the ARP
            broadcast probe. If omitted, ARP scanning is skipped.

    Returns:
        List of DeviceInfo, one per host in `hosts` (alive and dead included).
    """
    local_ip = get_local_ip()
    total = len(hosts)
    completed = 0
    lock = asyncio.Lock()

    arp_by_ip: dict = {}
    if cidr:
        try:
            arp_results = await _arp_scan_async(cidr, timeout=max(timeout * 2, 2.0))
            arp_by_ip = {r.ip: r.mac for r in arp_results}
            if arp_by_ip:
                logger.info("ARP scan found %d device(s) on %s.", len(arp_by_ip), cidr)
        except Exception as exc:  # noqa: BLE001 - ARP is best-effort
            logger.debug("ARP scan skipped/failed: %s", exc)

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(ip: str) -> DeviceInfo:
        nonlocal completed
        async with semaphore:
            if ip in arp_by_ip:
                # ARP already proved this host is alive; skip the (redundant,
                # sometimes slower) ping/TCP probe and enrich directly.
                device = DeviceInfo(ip=ip, alive=True, discovery_method="arp",
                                     is_self=(ip == local_ip), mac_address=arp_by_ip[ip])
                device.hostname = await hostname_mod.get_reverse_dns(ip)
                if device.mac_address:
                    device.vendor = vendor_mod.lookup_vendor(device.mac_address)
            else:
                device = await _enrich_device(ip, timeout, local_ip)
        async with lock:
            completed += 1
            if progress_callback:
                progress_callback(completed, total)
        return device

    devices = await asyncio.gather(*(_bounded(ip) for ip in hosts))
    # Sort by IP address numerically for a clean, readable listing
    def _ip_sort_key(d: DeviceInfo):
        try:
            return tuple(int(part) for part in d.ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)

    return sorted(devices, key=_ip_sort_key)
