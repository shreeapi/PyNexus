"""
json.py - JSON report generation for PyNexus scan results.
"""

from __future__ import annotations

import json as json_lib
from dataclasses import asdict
from typing import List

from core.scanner import HostScanResult


def generate_json_report(results: List[HostScanResult], output_path: str,
                          scan_meta: dict) -> str:
    """Write scan results to a JSON file.

    Args:
        results: List of HostScanResult objects.
        output_path: Destination file path.
        scan_meta: Dict of scan-level metadata (start time, elapsed, target spec, etc).

    Returns:
        The output_path written to.
    """
    payload = {
        "meta": scan_meta,
        "hosts": [asdict(r) for r in results],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json_lib.dump(payload, fh, indent=2, default=str)
    return output_path
