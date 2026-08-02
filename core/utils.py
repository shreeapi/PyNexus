"""
utils.py - Shared helper utilities: logging setup, target parsing, timing.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Iterator, List, Optional

from config import LOG_DATE_FORMAT, LOG_FORMAT, LOG_LEVEL


def setup_logging(name: str = "pynexus") -> logging.Logger:
    """Configure and return a module-level logger.

    Args:
        name: Logger name.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))
        logger.propagate = False
    return logger


logger = setup_logging()


class TargetParseError(Exception):
    """Raised when a scan target cannot be parsed."""


def resolve_hostname(target: str) -> str:
    """Resolve a hostname to an IPv4/IPv6 address.

    Args:
        target: Hostname or IP address string.

    Returns:
        Resolved IP address as a string.

    Raises:
        TargetParseError: If the hostname cannot be resolved.
    """
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise TargetParseError(f"Could not resolve hostname: {target}") from exc


def expand_targets(target: str) -> List[str]:
    """Expand a target specification into a list of individual IP addresses.

    Supports single IPs, hostnames, and CIDR notation (e.g. 192.168.1.0/24).

    Args:
        target: Target string (IP, hostname, or CIDR).

    Returns:
        List of individual IP address strings.

    Raises:
        TargetParseError: If the target cannot be parsed.
    """
    target = target.strip()
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise TargetParseError(f"Invalid CIDR range: {target}") from exc
        hosts = [str(ip) for ip in network.hosts()]
        if not hosts:
            # /31 or /32 networks: fall back to network address itself
            hosts = [str(network.network_address)]
        return hosts

    resolved = resolve_hostname(target)
    return [resolved]


def parse_port_spec(spec: str) -> List[int]:
    """Parse a port specification string into a sorted list of unique ports.

    Supports comma-separated values and ranges, e.g. "22,80,1000-1010".

    Args:
        spec: Port specification string.

    Returns:
        Sorted list of unique port integers.

    Raises:
        TargetParseError: If the specification is invalid.
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                start_s, end_s = chunk.split("-", 1)
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise TargetParseError(f"Invalid port range: {chunk}") from exc
            if start < 1 or end > 65535 or start > end:
                raise TargetParseError(f"Invalid port range: {chunk}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise TargetParseError(f"Invalid port value: {chunk}") from exc
            if not (1 <= port <= 65535):
                raise TargetParseError(f"Port out of range: {port}")
            ports.add(port)
    return sorted(ports)


@dataclass
class Timer:
    """Simple context-manager style timer for measuring elapsed time."""

    start_time: float = field(default=0.0)
    end_time: float = field(default=0.0)

    def __enter__(self) -> "Timer":
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *_exc_info) -> None:
        self.end_time = time.perf_counter()

    @property
    def elapsed(self) -> float:
        """Elapsed seconds. Uses current time if timer has not been stopped."""
        end = self.end_time or time.perf_counter()
        return round(end - self.start_time, 3)


def chunked(seq: List, size: int) -> Iterator[List]:
    """Yield successive chunks of `size` from `seq`."""
    for i in range(0, len(seq), size):
        yield seq[i:i + size]
