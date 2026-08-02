"""
ping.py - Host discovery via system ICMP ping and TCP ping fallback.
"""

from __future__ import annotations

import asyncio
import platform
import socket
import time
from dataclasses import dataclass
from typing import List, Optional

from core.utils import setup_logging

logger = setup_logging(__name__)

_COMMON_PING_PORTS = (80, 443, 22, 445, 3389)


@dataclass
class PingResult:
    """Result of a host-liveness check."""

    host: str
    alive: bool
    method: str
    latency_ms: Optional[float] = None


async def icmp_ping(host: str, timeout: float = 1.5) -> PingResult:
    """Attempt an ICMP ping using the OS `ping` utility (no raw sockets needed).

    Args:
        host: Target IP address or hostname.
        timeout: Timeout in seconds.

    Returns:
        PingResult indicating whether the host responded.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]

    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)
        except asyncio.TimeoutError:
            proc.kill()
            return PingResult(host=host, alive=False, method="icmp")
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        alive = proc.returncode == 0
        return PingResult(host=host, alive=alive, method="icmp",
                           latency_ms=elapsed_ms if alive else None)
    except (FileNotFoundError, OSError) as exc:
        logger.debug("ICMP ping unavailable for %s: %s", host, exc)
        return PingResult(host=host, alive=False, method="icmp")


async def tcp_ping(host: str, ports: tuple = _COMMON_PING_PORTS,
                    timeout: float = 1.0) -> PingResult:
    """Attempt TCP connects to common ports (in parallel) as a liveness fallback.

    Trying ports concurrently instead of sequentially means the worst-case
    time for a "no response" host is a single timeout window rather than
    timeout * len(ports), which matters a lot when sweeping large subnets.

    Args:
        host: Target IP address.
        ports: Candidate ports to try.
        timeout: Timeout per attempt in seconds.

    Returns:
        PingResult with method 'tcp'.
    """
    async def _try_port(port: int) -> Optional[PingResult]:
        start = time.perf_counter()
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PingResult(host=host, alive=True, method="tcp", latency_ms=elapsed_ms)
        except ConnectionRefusedError:
            # Connection refused still proves the host is alive (port closed, host up)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return PingResult(host=host, alive=True, method="tcp", latency_ms=elapsed_ms)
        except (asyncio.TimeoutError, OSError):
            return None

    tasks = [asyncio.create_task(_try_port(p)) for p in ports]
    try:
        for coro in asyncio.as_completed(tasks, timeout=timeout + 0.5):
            try:
                result = await coro
            except asyncio.TimeoutError:
                continue
            if result is not None:
                for t in tasks:
                    t.cancel()
                return result
    except asyncio.TimeoutError:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
    return PingResult(host=host, alive=False, method="tcp")


async def check_host_alive(host: str, timeout: float = 1.5) -> PingResult:
    """Check host liveness using ICMP and TCP ping concurrently, returning
    whichever succeeds first (or the ICMP result if both fail).

    Running both methods in parallel instead of sequentially roughly halves
    the worst-case time spent on unresponsive hosts during a subnet sweep.

    Args:
        host: Target host.
        timeout: Timeout in seconds for each method.

    Returns:
        PingResult describing liveness.
    """
    icmp_task = asyncio.create_task(icmp_ping(host, timeout=timeout))
    tcp_task = asyncio.create_task(tcp_ping(host, timeout=timeout))

    done, pending = await asyncio.wait(
        {icmp_task, tcp_task}, return_when=asyncio.FIRST_COMPLETED
    )

    # If the first-completed task already proves liveness, cancel the other.
    for task in done:
        result = task.result()
        if result.alive:
            for other in pending:
                other.cancel()
            return result

    # Neither finished task proved liveness yet; wait for the remaining one.
    if pending:
        remaining_done, _ = await asyncio.wait(pending)
        for task in remaining_done:
            result = task.result()
            if result.alive:
                return result

    # Both methods failed; report the ICMP result (method label defaults sensibly).
    return icmp_task.result() if icmp_task.done() else PingResult(host=host, alive=False, method="icmp")


async def ping_sweep(hosts: List[str], timeout: float = 1.5,
                      concurrency: int = 100) -> List[PingResult]:
    """Perform a concurrent ping sweep across multiple hosts.

    Args:
        hosts: List of IP addresses to check.
        timeout: Timeout per host.
        concurrency: Max concurrent checks.

    Returns:
        List of PingResult objects (only for hosts checked).
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(host: str) -> PingResult:
        async with semaphore:
            return await check_host_alive(host, timeout=timeout)

    tasks = [_bounded(h) for h in hosts]
    return await asyncio.gather(*tasks)
