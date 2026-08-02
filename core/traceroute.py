"""
traceroute.py - Traceroute implementation using the system traceroute/tracert
utility, avoiding the need for raw-socket privileges in most cases.
"""

from __future__ import annotations

import asyncio
import platform
import re
from dataclasses import dataclass
from typing import List, Optional

from config import DEFAULT_TRACEROUTE_HOPS, DEFAULT_TRACEROUTE_TIMEOUT
from core.utils import setup_logging

logger = setup_logging(__name__)

_LINUX_HOP_RE = re.compile(
    r"^\s*(\d+)\s+(?:([\w\.\-]+)\s+\(([\d\.]+)\)|(\*))\s+(?:([\d\.]+)\s*ms)?"
)
_WIN_HOP_RE = re.compile(
    r"^\s*(\d+)\s+.*?([\d]+)\s*ms.*?([\d\.]+)\s*$"
)


@dataclass
class Hop:
    """A single traceroute hop."""

    hop_number: int
    ip: Optional[str]
    hostname: Optional[str]
    latency_ms: Optional[float]
    responded: bool


async def traceroute(host: str, max_hops: int = DEFAULT_TRACEROUTE_HOPS,
                      timeout: float = DEFAULT_TRACEROUTE_TIMEOUT) -> List[Hop]:
    """Run a traceroute to the target host using the OS-provided utility.

    Args:
        host: Target IP address or hostname.
        max_hops: Maximum number of hops to probe.
        timeout: Per-probe timeout in seconds (best effort; OS tool dependent).

    Returns:
        List of Hop objects representing the discovered path. Empty list if
        the traceroute utility is unavailable.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w",
               str(int(timeout * 1000)), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), host]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout * max_hops + 10
        )
    except (FileNotFoundError, OSError) as exc:
        logger.warning("Traceroute utility not available: %s", exc)
        return []
    except asyncio.TimeoutError:
        logger.warning("Traceroute to %s timed out.", host)
        return []

    output = stdout.decode(errors="ignore")
    hops: List[Hop] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line[0].isdigit():
            continue
        parts = line.split()
        try:
            hop_num = int(parts[0])
        except (ValueError, IndexError):
            continue

        if "*" in line and not any(ch.isdigit() for ch in " ".join(parts[1:])):
            hops.append(Hop(hop_number=hop_num, ip=None, hostname=None,
                             latency_ms=None, responded=False))
            continue

        ip_match = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", line)
        latency_match = re.search(r"([\d.]+)\s*ms", line)
        ip_addr = ip_match.group(0) if ip_match else None
        latency = float(latency_match.group(1)) if latency_match else None
        hops.append(Hop(hop_number=hop_num, ip=ip_addr, hostname=None,
                         latency_ms=latency, responded=bool(ip_addr)))
    return hops
