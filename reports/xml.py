"""
xml.py - XML report generation for PyNexus scan results.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import List

from core.scanner import HostScanResult


def _set_text(parent: ET.Element, tag: str, value) -> ET.Element:
    """Create a child element with text content, coercing value to str."""
    elem = ET.SubElement(parent, tag)
    elem.text = "" if value is None else str(value)
    return elem


def generate_xml_report(results: List[HostScanResult], output_path: str,
                         scan_meta: dict) -> str:
    """Write scan results to a pretty-printed XML file.

    Args:
        results: List of HostScanResult objects.
        output_path: Destination file path.
        scan_meta: Dict of scan-level metadata.

    Returns:
        The output_path written to.
    """
    root = ET.Element("pynexus_scan")
    meta_elem = ET.SubElement(root, "meta")
    for key, value in scan_meta.items():
        _set_text(meta_elem, key, value)

    hosts_elem = ET.SubElement(root, "hosts")
    for r in results:
        host_elem = ET.SubElement(hosts_elem, "host", attrib={"address": r.host})
        _set_text(host_elem, "alive", r.alive)
        _set_text(host_elem, "hostname", r.hostname)
        _set_text(host_elem, "mac_address", r.mac_address)
        _set_text(host_elem, "vendor", r.vendor)
        _set_text(host_elem, "latency_ms", r.latency_ms)
        _set_text(host_elem, "scan_time", r.scan_time)
        _set_text(host_elem, "elapsed_seconds", r.elapsed_seconds)

        ports_elem = ET.SubElement(host_elem, "ports")
        for port_entry in r.open_ports + r.filtered_ports:
            port_elem = ET.SubElement(ports_elem, "port", attrib={
                "number": str(port_entry["port"]),
                "state": port_entry["state"],
            })
            _set_text(port_elem, "service", port_entry["service"])
            banner = r.banners.get(port_entry["port"])
            if banner:
                _set_text(port_elem, "banner", banner)

        if r.dns_records:
            dns_elem = ET.SubElement(host_elem, "dns_records")
            for rtype, values in r.dns_records.items():
                for value in values:
                    _set_text(dns_elem, "record", value).set("type", rtype)

        if r.ssl_info:
            ssl_root = ET.SubElement(host_elem, "ssl")
            for entry in r.ssl_info:
                ssl_elem = ET.SubElement(ssl_root, "certificate", attrib={
                    "port": str(entry.get("port"))
                })
                for key, value in entry.items():
                    if key == "port":
                        continue
                    _set_text(ssl_elem, key, value)

        if r.os_guess:
            os_elem = ET.SubElement(host_elem, "os_estimate")
            for key, value in r.os_guess.items():
                _set_text(os_elem, key, value)

        if r.traceroute_hops:
            trace_elem = ET.SubElement(host_elem, "traceroute")
            for hop in r.traceroute_hops:
                hop_elem = ET.SubElement(trace_elem, "hop")
                for key, value in hop.items():
                    _set_text(hop_elem, key, value)

    rough_string = ET.tostring(root, encoding="utf-8")
    pretty = minidom.parseString(rough_string).toprettyxml(indent="  ")
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(pretty)
    return output_path
