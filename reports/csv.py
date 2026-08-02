"""
csv.py - CSV report generation for PyNexus scan results.

Produces a flat, one-row-per-open-port CSV suitable for spreadsheets.
"""

from __future__ import annotations

import csv as csv_lib
from typing import List

from core.scanner import HostScanResult

_FIELDNAMES = [
    "host", "alive", "hostname", "mac_address", "vendor", "latency_ms",
    "port", "protocol", "state", "service", "banner", "scan_time",
    "elapsed_seconds",
]


def generate_csv_report(results: List[HostScanResult], output_path: str,
                         scan_meta: dict) -> str:
    """Write scan results to a CSV file, one row per discovered port.

    Hosts with no open ports still get a single summary row.

    Args:
        results: List of HostScanResult objects.
        output_path: Destination file path.
        scan_meta: Dict of scan-level metadata (unused in row data, informational).

    Returns:
        The output_path written to.
    """
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv_lib.DictWriter(fh, fieldnames=_FIELDNAMES)
        writer.writeheader()

        for r in results:
            base_row = {
                "host": r.host,
                "alive": r.alive,
                "hostname": r.hostname or "",
                "mac_address": r.mac_address or "",
                "vendor": r.vendor or "",
                "latency_ms": r.latency_ms if r.latency_ms is not None else "",
                "scan_time": r.scan_time,
                "elapsed_seconds": r.elapsed_seconds,
            }
            all_ports = r.open_ports + r.filtered_ports
            if not all_ports:
                row = dict(base_row, port="", protocol="", state="", service="", banner="")
                writer.writerow(row)
                continue

            for port_entry in all_ports:
                banner = r.banners.get(port_entry["port"], "")
                row = dict(base_row)
                row.update({
                    "port": port_entry["port"],
                    "protocol": "tcp",
                    "state": port_entry["state"],
                    "service": port_entry["service"],
                    "banner": banner.replace("\n", " | ") if banner else "",
                })
                writer.writerow(row)
    return output_path
