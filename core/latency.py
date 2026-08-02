"""
latency.py - Simple latency measurement helper via TCP connect timing.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional


async def measure_latency(host: str, port: int = 80, timeout: float = 2.0) -> Optional[float]:
    """Measure round-trip latency to a host via a TCP connect attempt.

    Args:
        host: Target IP address.
        port: Port to attempt connection on.
        timeout: Timeout in seconds.

    Returns:
        Latency in milliseconds, or None if the connection failed/timed out.
    """
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
        return elapsed_ms
    except ConnectionRefusedError:
        # Host responded (refused), so latency is still measurable
        return round((time.perf_counter() - start) * 1000, 2)
    except (asyncio.TimeoutError, OSError):
        return None
