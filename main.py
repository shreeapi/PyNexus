#!/usr/bin/env python3
"""
main.py - PyNexus Scanner CLI entrypoint.

Usage examples:
    python main.py scan 192.168.1.1
    python main.py scan scanme.nmap.org --ports top100
    python main.py scan 192.168.1.0/24 --ports 1-1000 --output html
    python main.py scan example.com --ports top1000 --dns --ssl --traceroute

Ethical use only: authorized security testing, network administration, and
education. See README.md for full disclaimer.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import datetime
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_RETRIES,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT,
    DISCLAIMER,
    REPORTS_OUTPUT_DIR,
)
from core.discover import DeviceInfo, discover_devices, guess_local_cidr
from core.ports import resolve_ports
from core.progress import build_progress
from core.scanner import HostScanResult, ScanOptions, scan_host, scan_hosts
from core.utils import TargetParseError, expand_targets, setup_logging
from reports.csv import generate_csv_report
from reports.html import generate_html_report
from reports.json import generate_json_report
from reports.xml import generate_xml_report

logger = setup_logging("pynexus.main")
console = Console()

_STAGE_LABELS = {
    "discovery": "Host discovery",
    "tcp_scan": "TCP scan",
    "udp_scan": "UDP scan",
    "banners": "Banner grabbing",
    "ssl": "SSL/TLS inspection",
    "dns": "DNS enumeration",
    "os_detect": "OS estimation",
    "traceroute": "Traceroute",
}


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="pynexus",
        description=f"{APP_NAME} v{APP_VERSION} — modular network scanner "
                    "for authorized security testing and administration.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a scan against a target")
    scan_parser.add_argument("target", help="IP address, hostname, or CIDR range "
                                             "(e.g. 192.168.1.0/24)")
    scan_parser.add_argument("--ports", default="top100",
                              help="Port spec: 'top100', 'top1000', 'all', or custom "
                                   "e.g. '22,80,1000-1010' (default: top100)")
    scan_parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                              help=f"Per-connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    scan_parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                              help=f"Max concurrent connections (default: {DEFAULT_THREADS})")
    scan_parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                              help=f"Retries per port on timeout (default: {DEFAULT_RETRIES})")
    scan_parser.add_argument("--udp", action="store_true", help="Also scan UDP ports")
    scan_parser.add_argument("--syn", action="store_true",
                              help="Use SYN scan instead of connect scan "
                                   "(requires scapy + root/admin privileges)")
    scan_parser.add_argument("--dns", action="store_true", help="Enumerate DNS records")
    scan_parser.add_argument("--ssl", action="store_true", help="Inspect SSL/TLS certificates")
    scan_parser.add_argument("--traceroute", action="store_true", help="Run traceroute")
    scan_parser.add_argument("--no-os-detect", action="store_true",
                              help="Disable passive OS fingerprint estimation")
    scan_parser.add_argument("--no-ping", action="store_true",
                              help="Skip host discovery and scan ports directly "
                                   "(useful when ICMP/TCP ping is blocked)")
    scan_parser.add_argument("--output", choices=["html", "json", "csv", "xml"],
                              default=None, help="Generate a report in the given format")
    scan_parser.add_argument("--output-path", default=None,
                              help="Custom output file path for the report")

    discover_parser = subparsers.add_parser(
        "discover", help="Sweep a subnet to list all connected devices (IP, hostname, MAC, vendor)"
    )
    discover_parser.add_argument(
        "target", nargs="?", default=None,
        help="CIDR range to sweep (e.g. 192.168.1.0/24). If omitted, PyNexus "
             "will auto-detect your local /24 subnet.",
    )
    discover_parser.add_argument("--timeout", type=float, default=1.0,
                                  help="Per-host liveness timeout in seconds (default: 1.0)")
    discover_parser.add_argument("--threads", type=int, default=150,
                                  help="Max concurrent liveness checks (default: 150)")
    discover_parser.add_argument("--output", choices=["html", "json", "csv", "xml"],
                                  default=None, help="Generate a report in the given format")
    discover_parser.add_argument("--output-path", default=None,
                                  help="Custom output file path for the report")

    return parser


def print_banner() -> None:
    """Display the application banner and ethical-use disclaimer."""
    console.print(Panel.fit(
        f"[bold cyan]{APP_NAME}[/bold cyan] [dim]v{APP_VERSION}[/dim]\n"
        f"[yellow]{DISCLAIMER}[/yellow]",
        border_style="cyan",
    ))


def print_summary_table(results: List[HostScanResult]) -> None:
    """Render a Rich summary table of scan results to the console."""
    table = Table(title="Scan Summary", show_lines=False)
    table.add_column("Host", style="bold cyan")
    table.add_column("Status")
    table.add_column("Hostname")
    table.add_column("Open Ports", justify="right")
    table.add_column("Filtered", justify="right")
    table.add_column("Latency (ms)", justify="right")
    table.add_column("Elapsed (s)", justify="right")

    for r in results:
        status = "[green]ALIVE[/green]" if r.alive else "[red]DOWN[/red]"
        table.add_row(
            r.host,
            status,
            r.hostname or "-",
            str(len(r.open_ports)),
            str(len(r.filtered_ports)),
            f"{r.latency_ms:.2f}" if r.latency_ms is not None else "-",
            f"{r.elapsed_seconds:.2f}",
        )
    console.print(table)

    for r in results:
        if not r.alive or not r.open_ports:
            continue
        port_table = Table(title=f"Open Ports on {r.host}", show_lines=False)
        port_table.add_column("Port", justify="right")
        port_table.add_column("Service")
        port_table.add_column("Banner")
        for entry in sorted(r.open_ports, key=lambda p: p["port"]):
            banner = r.banners.get(entry["port"], "")
            banner_display = banner.splitlines()[0][:80] if banner else "-"
            port_table.add_row(str(entry["port"]), entry["service"], banner_display)
        console.print(port_table)


def write_report(fmt: str, results: List[HostScanResult], scan_meta: dict,
                  output_path: Optional[str]) -> str:
    """Dispatch to the appropriate report generator and write the file.

    Args:
        fmt: One of 'html', 'json', 'csv', 'xml'.
        results: Scan results to serialize.
        scan_meta: Scan-level metadata dict.
        output_path: Optional explicit output path; a default is generated if None.

    Returns:
        The path the report was written to.
    """
    os.makedirs(REPORTS_OUTPUT_DIR, exist_ok=True)
    if output_path is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(REPORTS_OUTPUT_DIR, f"pynexus_report_{timestamp}.{fmt}")

    generators = {
        "html": generate_html_report,
        "json": generate_json_report,
        "csv": generate_csv_report,
        "xml": generate_xml_report,
    }
    return generators[fmt](results, output_path, scan_meta)


async def run_scan(args: argparse.Namespace) -> int:
    """Execute the scan subcommand end-to-end.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Process exit code (0 for success, non-zero on error).
    """
    try:
        targets = expand_targets(args.target)
    except TargetParseError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1

    try:
        ports = resolve_ports(args.ports)
    except TargetParseError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1

    if len(targets) > 1:
        console.print(f"[cyan]Expanded target to {len(targets)} host(s).[/cyan]")

    options = ScanOptions(
        ports=ports,
        scan_udp=args.udp,
        use_syn=args.syn,
        timeout=args.timeout,
        threads=args.threads,
        retries=args.retries,
        enable_dns=args.dns,
        enable_ssl=args.ssl,
        enable_traceroute=args.traceroute,
        enable_os_detect=not args.no_os_detect,
        skip_host_discovery=args.no_ping,
    )

    scan_start = datetime.datetime.now()
    progress = build_progress()
    stage_tasks = {}

    with progress:
        overall_task = progress.add_task(
            f"Scanning {len(targets)} host(s), {len(ports)} port(s) each", total=len(targets)
        )

        def progress_callback(host: str, stage: str) -> None:
            label = _STAGE_LABELS.get(stage, stage)
            progress.console.log(f"[dim]{host}[/dim] -> {label} complete")

        async def _scan_with_progress() -> list:
            results_local = []
            for host in targets:
                def _cb(stage: str, _host=host) -> None:
                    progress_callback(_host, stage)
                host_result = await scan_host(host, options, progress_callback=_cb)
                results_local.append(host_result)
                progress.advance(overall_task)
            return results_local

        try:
            results = await _scan_with_progress()
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
            return 130

    elapsed_total = (datetime.datetime.now() - scan_start).total_seconds()
    console.print()
    print_summary_table(results)

    console.print(
        f"\n[bold]Scan completed[/bold] in {elapsed_total:.2f}s — "
        f"{sum(1 for r in results if r.alive)}/{len(results)} host(s) alive."
    )

    if args.output:
        scan_meta = {
            "target_spec": args.target,
            "ports_scanned": len(ports),
            "scan_start": scan_start.isoformat(),
            "elapsed_seconds": round(elapsed_total, 3),
            "tool": f"{APP_NAME} v{APP_VERSION}",
        }
        output_path = write_report(args.output, results, scan_meta, args.output_path)
        console.print(f"[green]Report written to:[/green] {output_path}")

    return 0


def print_device_table(devices: List[DeviceInfo], subnet: str) -> None:
    """Render a Rich table of discovered LAN devices to the console."""
    alive_devices = [d for d in devices if d.alive]
    table = Table(title=f"Connected Devices on {subnet} "
                         f"({len(alive_devices)}/{len(devices)} responded)")
    table.add_column("IP Address", style="bold cyan")
    table.add_column("Status")
    table.add_column("Hostname")
    table.add_column("MAC Address")
    table.add_column("Vendor")
    table.add_column("Latency (ms)", justify="right")

    for d in alive_devices:
        status = "[green]THIS DEVICE[/green]" if d.is_self else "[green]ONLINE[/green]"
        table.add_row(
            d.ip,
            status,
            d.hostname or "-",
            d.mac_address or "-",
            d.vendor or "-",
            f"{d.latency_ms:.2f}" if d.latency_ms is not None else "-",
        )
    console.print(table)


def write_discover_report(fmt: str, devices: List[DeviceInfo], scan_meta: dict,
                           output_path: Optional[str]) -> str:
    """Write a discovery report by adapting DeviceInfo rows into the existing
    report generators (reusing the HostScanResult-shaped writers where possible).

    Args:
        fmt: One of 'html', 'json', 'csv', 'xml'.
        devices: List of DeviceInfo (alive devices only recommended).
        scan_meta: Scan-level metadata dict.
        output_path: Optional explicit output path.

    Returns:
        The path the report was written to.
    """
    os.makedirs(REPORTS_OUTPUT_DIR, exist_ok=True)
    if output_path is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(REPORTS_OUTPUT_DIR, f"pynexus_discover_{timestamp}.{fmt}")

    rows = [
        {
            "ip": d.ip,
            "alive": d.alive,
            "hostname": d.hostname or "",
            "mac_address": d.mac_address or "",
            "vendor": d.vendor or "",
            "latency_ms": d.latency_ms if d.latency_ms is not None else "",
            "is_self": d.is_self,
        }
        for d in devices
    ]

    if fmt == "json":
        import json as json_lib
        with open(output_path, "w", encoding="utf-8") as fh:
            json_lib.dump({"meta": scan_meta, "devices": rows}, fh, indent=2, default=str)
    elif fmt == "csv":
        import csv as csv_lib
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv_lib.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else
                                         ["ip", "alive", "hostname", "mac_address",
                                          "vendor", "latency_ms", "is_self"])
            writer.writeheader()
            writer.writerows(rows)
    elif fmt == "xml":
        import xml.etree.ElementTree as ET
        from xml.dom import minidom
        root = ET.Element("pynexus_discovery")
        meta_elem = ET.SubElement(root, "meta")
        for key, value in scan_meta.items():
            ET.SubElement(meta_elem, key).text = str(value)
        devices_elem = ET.SubElement(root, "devices")
        for row in rows:
            device_elem = ET.SubElement(devices_elem, "device", attrib={"ip": row["ip"]})
            for key, value in row.items():
                if key == "ip":
                    continue
                ET.SubElement(device_elem, key).text = str(value)
        pretty = minidom.parseString(ET.tostring(root, encoding="utf-8")).toprettyxml(indent="  ")
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(pretty)
    else:  # html
        rows_html = "".join(
            f"<tr><td>{r['ip']}</td><td>{'Yes' if r['is_self'] else ''}</td>"
            f"<td>{r['hostname']}</td><td><code>{r['mac_address']}</code></td>"
            f"<td>{r['vendor']}</td><td>{r['latency_ms']}</td></tr>"
            for r in rows
        )
        html_doc = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>PyNexus Network Discovery Report</title>
<style>
body {{ font-family: 'Segoe UI', Roboto, Arial, sans-serif; background:#0f1117; color:#e6e6e6; padding:24px; }}
h1 {{ color:#4fd1c5; }}
table {{ border-collapse: collapse; width:100%; margin-top:16px; }}
th, td {{ text-align:left; padding:8px 12px; border-bottom:1px solid #2d3748; }}
th {{ color:#a0aec0; text-transform:uppercase; font-size:12px; }}
code {{ background:#1a202c; padding:2px 6px; border-radius:4px; }}
.meta {{ background:#1a202c; padding:12px 16px; border-radius:8px; }}
</style></head><body>
<h1>PyNexus Scanner &mdash; Network Discovery Report</h1>
<div class='meta'>{"".join(f"<div><b>{k}:</b> {v}</div>" for k, v in scan_meta.items())}</div>
<table><tr><th>IP</th><th>This Device</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Latency (ms)</th></tr>
{rows_html}
</table>
</body></html>"""
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)

    return output_path


async def run_discover(args: argparse.Namespace) -> int:
    """Execute the discover subcommand: sweep a subnet and list live devices.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Process exit code.
    """
    target = args.target
    if not target:
        target = guess_local_cidr()
        if not target:
            console.print("[red]Error:[/red] Could not auto-detect your local subnet. "
                           "Please specify one explicitly, e.g. 192.168.1.0/24")
            return 1
        console.print(f"[cyan]No target given — auto-detected local subnet:[/cyan] {target}")

    try:
        hosts = expand_targets(target)
    except TargetParseError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1

    console.print(f"[cyan]Sweeping {len(hosts)} address(es) on {target}...[/cyan]")

    scan_start = datetime.datetime.now()
    progress = build_progress()

    with progress:
        task_id = progress.add_task(f"Discovering devices on {target}", total=len(hosts))

        def _progress_cb(completed: int, total: int) -> None:
            progress.update(task_id, completed=completed)

        try:
            devices = await discover_devices(
                hosts, timeout=args.timeout, concurrency=args.threads,
                progress_callback=_progress_cb, cidr=target,
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]Discovery interrupted by user.[/yellow]")
            return 130

    elapsed_total = (datetime.datetime.now() - scan_start).total_seconds()
    console.print()
    print_device_table(devices, target)

    alive_count = sum(1 for d in devices if d.alive)
    console.print(
        f"\n[bold]Discovery completed[/bold] in {elapsed_total:.2f}s — "
        f"{alive_count}/{len(devices)} device(s) online."
    )

    if args.output:
        scan_meta = {
            "target_spec": target,
            "hosts_swept": len(hosts),
            "scan_start": scan_start.isoformat(),
            "elapsed_seconds": round(elapsed_total, 3),
            "tool": f"{APP_NAME} v{APP_VERSION}",
        }
        alive_devices = [d for d in devices if d.alive]
        output_path = write_discover_report(args.output, alive_devices, scan_meta, args.output_path)
        console.print(f"[green]Report written to:[/green] {output_path}")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint.

    Args:
        argv: Optional argument list override (defaults to sys.argv).

    Returns:
        Process exit code.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    print_banner()

    if args.command == "scan":
        try:
            return asyncio.run(run_scan(args))
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            return 130
        except Exception as exc:  # noqa: BLE001 - top-level safety net
            logger.exception("Unhandled error during scan")
            console.print(f"[red]Fatal error:[/red] {exc}")
            return 1

    if args.command == "discover":
        try:
            return asyncio.run(run_discover(args))
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            return 130
        except Exception as exc:  # noqa: BLE001 - top-level safety net
            logger.exception("Unhandled error during discovery")
            console.print(f"[red]Fatal error:[/red] {exc}")
            return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
