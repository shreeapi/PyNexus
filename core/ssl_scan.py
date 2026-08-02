"""
ssl_scan.py - SSL/TLS certificate and cipher inspection for HTTPS-like services.
"""

from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
from dataclasses import dataclass
from typing import Optional

from core.utils import setup_logging

logger = setup_logging(__name__)


@dataclass
class SslInfo:
    """SSL/TLS details for a service."""

    port: int
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_after: Optional[str] = None
    days_remaining: Optional[int] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    self_signed: Optional[bool] = None
    error: Optional[str] = None


def _fetch_ssl_info_sync(host: str, port: int, timeout: float) -> SslInfo:
    """Synchronous helper that connects and inspects the TLS certificate."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                version = tls_sock.version()

        subject = _flatten_name(cert.get("subject")) if cert else None
        issuer = _flatten_name(cert.get("issuer")) if cert else None
        not_after_raw = cert.get("notAfter") if cert else None
        days_remaining = None
        not_after_str = None
        if not_after_raw:
            try:
                expiry = datetime.datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expiry - datetime.datetime.utcnow()).days
                not_after_str = expiry.isoformat()
            except ValueError:
                not_after_str = not_after_raw

        self_signed = bool(subject and issuer and subject == issuer)

        return SslInfo(
            port=port,
            subject=subject,
            issuer=issuer,
            not_after=not_after_str,
            days_remaining=days_remaining,
            tls_version=version,
            cipher_suite=cipher[0] if cipher else None,
            self_signed=self_signed,
        )
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as exc:
        return SslInfo(port=port, error=str(exc))


def _flatten_name(name_tuple) -> Optional[str]:
    """Flatten an X.509 name tuple structure into a readable string."""
    if not name_tuple:
        return None
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) if parts else None


async def fetch_ssl_info(host: str, port: int = 443, timeout: float = 3.0) -> SslInfo:
    """Fetch SSL/TLS certificate details for a host:port asynchronously.

    Args:
        host: Target IP address or hostname.
        port: TLS-enabled port (default 443).
        timeout: Connection timeout in seconds.

    Returns:
        SslInfo dataclass with certificate and negotiation details.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _fetch_ssl_info_sync, host, port, timeout)
