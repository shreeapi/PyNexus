"""
os_detect.py - Basic passive OS fingerprint estimation using TTL and TCP window
size heuristics. Results are ESTIMATES only, not definitive identification.
"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from core.utils import setup_logging

logger = setup_logging(__name__)

# Common initial TTL values by OS family (approximate, widely documented heuristic)
_TTL_GUESS_TABLE = [
    (64, "Linux / Unix / macOS (TTL ~64)"),
    (128, "Windows (TTL ~128)"),
    (255, "Network device / Solaris / Cisco IOS (TTL ~255)"),
]


@dataclass
class OsGuess:
    """Estimated OS fingerprint result. Always an estimate, never certain."""

    observed_ttl: Optional[int]
    estimated_os: str
    confidence: str  # 'low', 'medium'
    note: str = "Estimate based on TTL heuristics only; not a definitive result."


def _get_ttl_from_ping(host: str, timeout: float = 1.5) -> Optional[int]:
    """Run a single OS ping and parse the TTL value from the reply."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("TTL probe failed for %s: %s", host, exc)
        return None

    output = result.stdout
    match = re.search(r"[Tt][Tt][Ll][=:]\s*(\d+)", output)
    if match:
        return int(match.group(1))
    return None


def estimate_os(host: str, timeout: float = 1.5) -> OsGuess:
    """Estimate the target's OS family using TTL heuristics.

    This is a lightweight, non-invasive alternative to full active
    fingerprinting (which nmap performs via crafted packet responses).
    Results should be treated as rough estimates.

    Args:
        host: Target IP address.
        timeout: Ping timeout in seconds.

    Returns:
        OsGuess dataclass describing the estimate.
    """
    ttl = _get_ttl_from_ping(host, timeout=timeout)
    if ttl is None:
        return OsGuess(observed_ttl=None, estimated_os="Unknown (no ICMP response)",
                        confidence="low")

    # Find the closest "default" TTL at or above the observed value,
    # since TTL decrements with each hop.
    closest_guess = "Unknown"
    smallest_diff = None
    for default_ttl, label in _TTL_GUESS_TABLE:
        if ttl <= default_ttl:
            diff = default_ttl - ttl
            if smallest_diff is None or diff < smallest_diff:
                smallest_diff = diff
                closest_guess = label

    confidence = "medium" if smallest_diff is not None and smallest_diff <= 5 else "low"
    return OsGuess(observed_ttl=ttl, estimated_os=closest_guess, confidence=confidence)
