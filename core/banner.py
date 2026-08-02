"""
banner.py - Banner grabbing for common TCP services (HTTP, SSH, FTP, SMTP, etc).
"""

from __future__ import annotations

import asyncio
from typing import Optional

from core.utils import setup_logging

logger = setup_logging(__name__)

# Ports that expect the client to speak first (send an HTTP-style probe)
_CLIENT_FIRST_PORTS = {80, 8080, 8000, 8008, 8888, 443, 8443, 3306, 5432, 6379, 27017}


async def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab a service banner from an open TCP port.

    Args:
        host: Target IP address.
        port: Open TCP port.
        timeout: Read timeout in seconds.

    Returns:
        Cleaned banner string, or None if no banner could be retrieved.
    """
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        if port in _CLIENT_FIRST_PORTS:
            probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            try:
                writer.write(probe.encode(errors="ignore"))
                await writer.drain()
            except OSError:
                pass

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""

        if not data:
            return None

        banner = data.decode(errors="ignore").strip()
        # Collapse to first non-empty line(s), cap length for readability
        first_lines = "\n".join(
            line.strip() for line in banner.splitlines()[:3] if line.strip()
        )
        return first_lines[:300] if first_lines else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def grab_banners_for_ports(host: str, open_ports: list, timeout: float = 2.0,
                                  concurrency: int = 50) -> dict:
    """Grab banners for a list of open ports concurrently.

    Args:
        host: Target IP address.
        open_ports: List of open port numbers.
        timeout: Per-port read timeout.
        concurrency: Max concurrent banner grabs.

    Returns:
        Dict mapping port -> banner string (only for ports with a banner).
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(port: int):
        async with semaphore:
            banner = await grab_banner(host, port, timeout=timeout)
            return port, banner

    results = await asyncio.gather(*(_bounded(p) for p in open_ports))
    return {port: banner for port, banner in results if banner}
