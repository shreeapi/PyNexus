"""
dns.py - DNS record enumeration using dnspython, with graceful fallback.
"""

from __future__ import annotations

import asyncio
from typing import Dict, List

from core.utils import setup_logging

logger = setup_logging(__name__)

_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

try:
    import dns.resolver  # type: ignore
    import dns.reversename  # type: ignore
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False


def _query_sync(domain: str, record_type: str, timeout: float) -> List[str]:
    """Synchronous DNS query helper for a single record type."""
    if not _DNSPYTHON_AVAILABLE:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(domain, record_type)
        return [str(rdata).strip() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception as exc:  # noqa: BLE001 - defensive catch for resolver edge cases
        logger.debug("DNS query error for %s %s: %s", domain, record_type, exc)
        return []


def _reverse_lookup_sync(ip: str, timeout: float) -> List[str]:
    """Synchronous reverse DNS (PTR) lookup helper."""
    if not _DNSPYTHON_AVAILABLE:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, "PTR")
        return [str(rdata).strip() for rdata in answers]
    except Exception:  # noqa: BLE001
        return []


async def enumerate_dns(domain: str, timeout: float = 3.0) -> Dict[str, List[str]]:
    """Enumerate common DNS record types for a domain.

    Args:
        domain: Domain name to query.
        timeout: Per-query timeout in seconds.

    Returns:
        Dict mapping record type -> list of record values (empty list if none found).
    """
    if not _DNSPYTHON_AVAILABLE:
        logger.warning("dnspython not installed; DNS enumeration unavailable.")
        return {rtype: [] for rtype in _RECORD_TYPES}

    loop = asyncio.get_running_loop()
    results: Dict[str, List[str]] = {}
    tasks = {
        rtype: loop.run_in_executor(None, _query_sync, domain, rtype, timeout)
        for rtype in _RECORD_TYPES
    }
    for rtype, task in tasks.items():
        results[rtype] = await task
    return results


async def reverse_dns(ip: str, timeout: float = 3.0) -> List[str]:
    """Perform a reverse DNS (PTR) lookup for an IP address.

    Args:
        ip: IP address string.
        timeout: Query timeout in seconds.

    Returns:
        List of PTR record hostnames (may be empty).
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _reverse_lookup_sync, ip, timeout)
