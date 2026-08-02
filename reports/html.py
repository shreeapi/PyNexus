"""
html.py - HTML report generation for PyNexus scan results.
"""

from __future__ import annotations

import html as html_lib
from typing import List

from core.scanner import HostScanResult

_CSS = """
body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:24px; }
h1 { color:#4fd1c5; }
h2 { color:#63b3ed; border-bottom:1px solid #2d3748; padding-bottom:6px; margin-top:36px; }
.meta { background:#1a202c; padding:12px 16px; border-radius:8px; margin-bottom:24px; }
.host-card { background:#161b22; border:1px solid #2d3748; border-radius:10px; padding:16px 20px; margin-bottom:20px; }
.badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:12px; font-weight:600; }
.badge-open { background:#22543d; color:#9ae6b4; }
.badge-filtered { background:#744210; color:#faf089; }
.badge-alive { background:#22543d; color:#9ae6b4; }
.badge-down { background:#742a2a; color:#feb2b2; }
table { border-collapse: collapse; width:100%; margin-top:10px; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid #2d3748; font-size:14px; }
th { color:#a0aec0; text-transform:uppercase; font-size:12px; }
.small { color:#a0aec0; font-size:13px; }
.disclaimer { margin-top:40px; padding:14px; background:#2d1b1b; border:1px solid #742a2a; border-radius:8px; font-size:13px; color:#feb2b2; }
code { background:#1a202c; padding:2px 6px; border-radius:4px; }
"""


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{kind}">{html_lib.escape(text)}</span>'


def generate_html_report(results: List[HostScanResult], output_path: str,
                          scan_meta: dict) -> str:
    """Write scan results to a self-contained HTML report file.

    Args:
        results: List of HostScanResult objects.
        output_path: Destination file path.
        scan_meta: Dict of scan-level metadata (target, timestamp, elapsed, etc).

    Returns:
        The output_path written to.
    """
    parts: List[str] = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    parts.append(f"<title>PyNexus Scan Report</title><style>{_CSS}</style></head><body>")
    parts.append("<h1>PyNexus Scanner &mdash; Scan Report</h1>")

    parts.append("<div class='meta'>")
    for key, value in scan_meta.items():
        parts.append(f"<div class='small'><b>{html_lib.escape(str(key))}:</b> "
                      f"{html_lib.escape(str(value))}</div>")
    parts.append("</div>")

    for r in results:
        parts.append("<div class='host-card'>")
        status_badge = _badge("ALIVE", "alive") if r.alive else _badge("DOWN", "down")
        parts.append(f"<h2>{html_lib.escape(r.host)} {status_badge}</h2>")

        parts.append("<div class='small'>")
        if r.hostname:
            parts.append(f"Hostname: <code>{html_lib.escape(r.hostname)}</code> &nbsp; ")
        if r.mac_address:
            parts.append(f"MAC: <code>{html_lib.escape(r.mac_address)}</code> &nbsp; ")
        if r.vendor:
            parts.append(f"Vendor: {html_lib.escape(r.vendor)} &nbsp; ")
        if r.latency_ms is not None:
            parts.append(f"Latency: {r.latency_ms} ms &nbsp; ")
        parts.append(f"Discovery: {html_lib.escape(r.discovery_method or 'n/a')} &nbsp; ")
        parts.append(f"Elapsed: {r.elapsed_seconds}s")
        parts.append("</div>")

        if r.os_guess:
            og = r.os_guess
            parts.append(
                f"<p class='small'>OS estimate: <b>{html_lib.escape(str(og.get('estimated_os')))}</b>"
                f" (confidence: {html_lib.escape(str(og.get('confidence')))}) &mdash; "
                f"{html_lib.escape(str(og.get('note')))}</p>"
            )

        all_ports = r.open_ports + r.filtered_ports
        if all_ports:
            parts.append("<table><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr>")
            for entry in sorted(all_ports, key=lambda p: p["port"]):
                badge_kind = "open" if entry["state"] == "open" else "filtered"
                banner = r.banners.get(entry["port"], "")
                parts.append(
                    f"<tr><td>{entry['port']}</td>"
                    f"<td>{_badge(entry['state'], badge_kind)}</td>"
                    f"<td>{html_lib.escape(entry['service'])}</td>"
                    f"<td><code>{html_lib.escape(banner)}</code></td></tr>"
                )
            parts.append("</table>")
        else:
            parts.append("<p class='small'>No open or filtered ports detected.</p>")

        if r.udp_results:
            parts.append("<h3 class='small'>UDP Results</h3><table>"
                          "<tr><th>Port</th><th>State</th><th>Service</th></tr>")
            for entry in r.udp_results:
                parts.append(
                    f"<tr><td>{entry['port']}</td><td>{html_lib.escape(entry['state'])}</td>"
                    f"<td>{html_lib.escape(entry['service'])}</td></tr>"
                )
            parts.append("</table>")

        if r.dns_records and any(r.dns_records.values()):
            parts.append("<h3 class='small'>DNS Records</h3><table>"
                          "<tr><th>Type</th><th>Value</th></tr>")
            for rtype, values in r.dns_records.items():
                for value in values:
                    parts.append(f"<tr><td>{rtype}</td><td>{html_lib.escape(value)}</td></tr>")
            parts.append("</table>")

        if r.ssl_info:
            parts.append("<h3 class='small'>SSL / TLS</h3><table>"
                          "<tr><th>Port</th><th>Subject</th><th>Issuer</th><th>Expires</th>"
                          "<th>Days Left</th><th>TLS Version</th><th>Cipher</th><th>Self-Signed</th></tr>")
            for entry in r.ssl_info:
                parts.append(
                    f"<tr><td>{entry.get('port')}</td>"
                    f"<td>{html_lib.escape(str(entry.get('subject')))}</td>"
                    f"<td>{html_lib.escape(str(entry.get('issuer')))}</td>"
                    f"<td>{html_lib.escape(str(entry.get('not_after')))}</td>"
                    f"<td>{html_lib.escape(str(entry.get('days_remaining')))}</td>"
                    f"<td>{html_lib.escape(str(entry.get('tls_version')))}</td>"
                    f"<td>{html_lib.escape(str(entry.get('cipher_suite')))}</td>"
                    f"<td>{html_lib.escape(str(entry.get('self_signed')))}</td></tr>"
                )
            parts.append("</table>")

        if r.traceroute_hops:
            parts.append("<h3 class='small'>Traceroute</h3><table>"
                          "<tr><th>Hop</th><th>IP</th><th>Latency (ms)</th></tr>")
            for hop in r.traceroute_hops:
                ip_display = hop.get("ip") or "*"
                latency_display = hop.get("latency_ms") if hop.get("latency_ms") is not None else "-"
                parts.append(
                    f"<tr><td>{hop.get('hop_number')}</td><td>{html_lib.escape(str(ip_display))}</td>"
                    f"<td>{latency_display}</td></tr>"
                )
            parts.append("</table>")

        parts.append("</div>")  # host-card

    parts.append(
        "<div class='disclaimer'>PyNexus Scanner is intended for authorized "
        "security testing, network administration, and educational purposes "
        "only. Scanning networks without explicit permission may be illegal "
        "in your jurisdiction.</div>"
    )
    parts.append("</body></html>")

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    return output_path
