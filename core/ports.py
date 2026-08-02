"""
ports.py - Port list resolution (top100, top1000, all, custom ranges).
"""

from __future__ import annotations

from typing import List

from config import ALL_PORTS_RANGE, TOP_100_PORTS, TOP_1000_PORTS
from core.utils import TargetParseError, parse_port_spec


def resolve_ports(spec: str) -> List[int]:
    """Resolve a port specification keyword or custom string into a port list.

    Recognized keywords: 'top100', 'top1000', 'all'.
    Otherwise treated as a custom spec passed to parse_port_spec (e.g. "1-1000").

    Args:
        spec: Port specification.

    Returns:
        Sorted list of unique ports.

    Raises:
        TargetParseError: If spec is invalid.
    """
    keyword = spec.strip().lower()
    if keyword == "top100":
        return sorted(TOP_100_PORTS)
    if keyword == "top1000":
        return sorted(TOP_1000_PORTS)
    if keyword == "all":
        return list(range(ALL_PORTS_RANGE[0], ALL_PORTS_RANGE[1] + 1))
    if not keyword:
        raise TargetParseError("Empty port specification")
    return parse_port_spec(spec)
