"""
scanner.py - High-level scan orchestration: coordinates host discovery, port
scanning, service/banner detection, DNS, SSL, OS estimation, and traceroute
into a unified ScanResult per host.
"""

from __future__ import annotations

import asyncio
import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core import banner as banner_mod
from core import dns as dns_mod
from core import hostname as hostname_mod
from core import mac_lookup as mac_mod
from core import os_detect as os_detect_mod
from core import ssl_scan as ssl_mod
from core import tcp_scan as tcp_mod
from core import traceroute as traceroute_mod
from core import udp_scan as udp_mod
from core import vendor as vendor_mod
from core.latency import measure_latency
from core.ping import check_host_alive
from core.services import lookup_service
from core.utils import Timer, setup_logging

logger = setup_logging(__name__)

_SSL_CANDIDATE_PORTS = {443, 8443, 993, 995, 465, 636, 8834, 9443}


@dataclass
class ScanOptions:
    """User-configurable options controlling a scan run."""

    ports: List[int] = field(default_factory=list)
    scan_udp: bool = False
    use_syn: bool = False
    timeout: float = 1.5
    threads: int = 200
    retries: int = 1
    enable_dns: bool = False
    enable_ssl: bool = False
    enable_traceroute: bool = False
    enable_os_detect: bool = True
    skip_host_discovery: bool = False


@dataclass
class HostScanResult:
    """Aggregated scan result for a single host."""

    host: str
    alive: bool = True
    discovery_method: Optional[str] = None
    latency_ms: Optional[float] = None
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[Dict] = field(default_factory=list)
    filtered_ports: List[Dict] = field(default_factory=list)
    closed_port_count: int = 0
    udp_results: List[Dict] = field(default_factory=list)
    banners: Dict[int, str] = field(default_factory=dict)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    ssl_info: List[Dict] = field(default_factory=list)
    os_guess: Optional[Dict] = None
    traceroute_hops: List[Dict] = field(default_factory=list)
    scan_time: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    elapsed_seconds: float = 0.0
    error: Optional[str] = None


async def scan_host(host: str, options: ScanOptions,
                     progress_callback=None) -> HostScanResult:
    """Run a full scan against a single host according to the given options.

    Args:
        host: Target IP address.
        options: ScanOptions describing which checks to run.
        progress_callback: Optional callable(stage: str) invoked as phases complete.

    Returns:
        HostScanResult with all collected data for this host.
    """
    result = HostScanResult(host=host)
    with Timer() as timer:
        if not options.skip_host_discovery:
            ping_result = await check_host_alive(host, timeout=options.timeout)
            result.alive = ping_result.alive
            result.discovery_method = ping_result.method
            result.latency_ms = ping_result.latency_ms
            if not result.alive:
                result.elapsed_seconds = timer.elapsed
                if progress_callback:
                    progress_callback("discovery")
                return result
        if progress_callback:
            progress_callback("discovery")

        # Resolve hostname / MAC / vendor concurrently
        rdns_task = asyncio.create_task(hostname_mod.get_reverse_dns(host))
        result.hostname = await rdns_task
        result.mac_address = mac_mod.get_mac_from_arp_cache(host)
        if result.mac_address:
            result.vendor = vendor_mod.lookup_vendor(result.mac_address)

        if result.latency_ms is None:
            result.latency_ms = await measure_latency(host, timeout=options.timeout)

        # Port scanning
        if options.ports:
            if options.use_syn:
                tcp_results = tcp_mod.tcp_syn_scan(host, options.ports, timeout=options.timeout)
            else:
                tcp_results = await tcp_mod.tcp_connect_scan(
                    host, options.ports, timeout=options.timeout,
                    concurrency=options.threads, retries=options.retries,
                )
            for port_result in tcp_results:
                entry = {
                    "port": port_result.port,
                    "state": port_result.state,
                    "service": lookup_service(port_result.port, "tcp"),
                }
                if port_result.state == "open":
                    result.open_ports.append(entry)
                elif port_result.state == "filtered":
                    result.filtered_ports.append(entry)
                else:
                    result.closed_port_count += 1
        if progress_callback:
            progress_callback("tcp_scan")

        # UDP scanning
        if options.scan_udp and options.ports:
            udp_results = await udp_mod.udp_scan(
                host, options.ports, timeout=options.timeout, concurrency=options.threads
            )
            for udp_result in udp_results:
                if udp_result.state != "closed":
                    result.udp_results.append({
                        "port": udp_result.port,
                        "state": udp_result.state,
                        "service": lookup_service(udp_result.port, "udp"),
                    })
        if progress_callback:
            progress_callback("udp_scan")

        # Banner grabbing on open ports
        open_port_numbers = [p["port"] for p in result.open_ports]
        if open_port_numbers:
            result.banners = await banner_mod.grab_banners_for_ports(
                host, open_port_numbers, timeout=max(options.timeout, 2.0)
            )
        if progress_callback:
            progress_callback("banners")

        # SSL/TLS inspection on relevant open ports
        if options.enable_ssl:
            ssl_ports = [p for p in open_port_numbers if p in _SSL_CANDIDATE_PORTS]
            for ssl_port in ssl_ports:
                ssl_info = await ssl_mod.fetch_ssl_info(host, ssl_port, timeout=max(options.timeout, 3.0))
                result.ssl_info.append(ssl_info.__dict__)
        if progress_callback:
            progress_callback("ssl")

        # DNS enumeration (uses hostname if resolvable, else the target string)
        if options.enable_dns:
            dns_target = result.hostname or host
            result.dns_records = await dns_mod.enumerate_dns(dns_target, timeout=options.timeout)
        if progress_callback:
            progress_callback("dns")

        # OS fingerprint estimate
        if options.enable_os_detect:
            os_guess = os_detect_mod.estimate_os(host, timeout=options.timeout)
            result.os_guess = os_guess.__dict__
        if progress_callback:
            progress_callback("os_detect")

        # Traceroute
        if options.enable_traceroute:
            hops = await traceroute_mod.traceroute(host)
            result.traceroute_hops = [hop.__dict__ for hop in hops]
        if progress_callback:
            progress_callback("traceroute")

    result.elapsed_seconds = timer.elapsed
    return result


async def scan_hosts(hosts: List[str], options: ScanOptions,
                      progress_callback=None) -> List[HostScanResult]:
    """Scan multiple hosts sequentially (each host's internal scanning is
    itself concurrent across ports), collecting a HostScanResult per host.

    Args:
        hosts: List of target IP addresses.
        options: ScanOptions applied to every host.
        progress_callback: Optional callable(host, stage) invoked per stage.

    Returns:
        List of HostScanResult, one per host.
    """
    results: List[HostScanResult] = []
    for host in hosts:
        def _cb(stage: str, _host=host) -> None:
            if progress_callback:
                progress_callback(_host, stage)

        host_result = await scan_host(host, options, progress_callback=_cb)
        results.append(host_result)
    return results
