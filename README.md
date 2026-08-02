# PyNexus Scanner

A modular, cross-platform network scanner written in Python, inspired by Nmap.
Built for **defensive security, network administration, and authorized
penetration testing**.

> ⚠️ **Ethical Use Disclaimer**
> PyNexus Scanner is intended for authorized security testing, network
> administration, and educational purposes **only**. Scanning networks or
> hosts without explicit permission from the owner may be illegal under
> computer misuse laws in your country (e.g. the U.S. Computer Fraud and
> Abuse Act, the UK Computer Misuse Act). Always obtain written authorization
> before scanning any system you do not own. The authors and contributors
> assume no liability for misuse of this tool.

---

## Quickstart

```bash
git clone https://github.com/shreeapi/PyNexus.git
cd PyNexus
chmod +x install.sh && ./install.sh
source venv/bin/activate
python3 main.py discover
```

---

## Features

- **Host Discovery**: ICMP ping, TCP ping fallback, ARP discovery (LAN, requires scapy + privileges), CIDR/subnet expansion.
- **Port Scanning**: Async TCP connect scan, optional raw SYN scan, UDP scan, custom port ranges, top-100/top-1000/all-port presets, adjustable timeout/threads/retries.
- **Service Detection**: Port-to-service mapping backed by a JSON database (`database/services.json`).
- **Banner Grabbing**: HTTP, SSH, FTP, SMTP, and generic TCP banners.
- **SSL/TLS Inspection**: Certificate subject/issuer, expiration, days remaining, TLS version, cipher suite, self-signed detection.
- **DNS Enumeration**: A, AAAA, MX, TXT, NS, CNAME, SOA, and reverse (PTR) records via `dnspython`.
- **Host Information**: Hostname, reverse DNS, MAC address (via OS ARP cache), vendor lookup (OUI database), latency.
- **Basic OS Fingerprinting**: TTL-based OS family estimate, clearly labeled as an estimate.
- **Traceroute**: Hop-by-hop path with latency, using the OS `traceroute`/`tracert` utility.
- **Reports**: HTML, JSON, CSV, and XML output formats.
- **Terminal UI**: Rich-powered progress bars, tables, colored output, and scan summaries.

---

## Project Structure

```
PyNexus/
├── main.py                # CLI entrypoint
├── requirements.txt
├── README.md
├── config.py               # Global settings, port lists, defaults
│
├── core/
│   ├── scanner.py          # High-level scan orchestration
│   ├── tcp_scan.py         # TCP connect + SYN scanning
│   ├── udp_scan.py         # UDP scanning
│   ├── ping.py             # ICMP/TCP host discovery
│   ├── arp.py              # ARP-based LAN discovery
│   ├── banner.py           # Banner grabbing
│   ├── services.py         # Service name lookup
│   ├── dns.py              # DNS enumeration
│   ├── ssl_scan.py         # TLS certificate inspection
│   ├── traceroute.py       # Traceroute
│   ├── os_detect.py        # Passive OS fingerprint estimate
│   ├── hostname.py         # Reverse DNS / hostname helpers
│   ├── mac_lookup.py       # ARP cache MAC lookup
│   ├── vendor.py           # OUI vendor lookup
│   ├── latency.py          # Latency measurement
│   ├── ports.py            # Port spec resolution
│   ├── progress.py         # Rich progress helpers
│   └── utils.py            # Logging, target/port parsing, timers
│
├── reports/
│   ├── html.py
│   ├── json.py
│   ├── csv.py
│   └── xml.py
│
├── database/
│   ├── services.json
│   └── vendors.json
│
└── assets/                 # Screenshots / static assets
```

---

## Installation

### Requirements

- Python 3.10+ (3.12 recommended)
- pip
- git

### Quick setup (Kali Linux / Debian / Ubuntu)

```bash
git clone https://github.com/shreeapi/PyNexus.git
cd PyNexus
chmod +x install.sh
./install.sh
```

This pulls in `python3-venv`, `libpcap-dev`, and every package in
`requirements.txt` inside an isolated `venv/`. Once it finishes:

```bash
source venv/bin/activate
python3 main.py discover
```

### Manual setup (any OS)

```bash
git clone https://github.com/shreeapi/PyNexus.git
cd PyNexus
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python3 main.py discover
```

Optional but recommended for advanced features:

- **scapy** — enables ARP discovery (`core/arp.py`) and raw SYN scanning (`--syn`). Requires root/admin privileges to send raw packets. On Kali this is usually already installed system-wide, but the `venv` needs its own copy (`pip install scapy`, included in `requirements.txt`).
- **libpcap** — `sudo apt install libpcap-dev` (Linux) — required by scapy for raw packet capture. macOS ships it by default; Windows needs [Npcap](https://npcap.com/).
- A system `ping`, `traceroute` (Linux/macOS) or `tracert` (Windows) binary on `PATH` — used for ICMP discovery, OS TTL estimation, and traceroute.

For ARP scanning and `--syn`, run PyNexus with elevated privileges:

```bash
sudo venv/bin/python3 main.py discover
sudo venv/bin/python3 main.py scan 192.168.1.1 --syn
```

---

## Usage

PyNexus has two subcommands:

- **`discover`** — sweep a subnet and list every connected device (IP, hostname, MAC, vendor, latency). Use this first to see what's on your network.
- **`scan`** — deep-scan a specific host or range (ports, services, banners, SSL, DNS, OS estimate, traceroute).

> **Why does `discover` sometimes find fewer devices than expected?**
> Without ARP, discovery relies on ICMP ping / TCP probes, which many phones,
> smart TVs, and IoT devices simply don't answer (sleep mode, personal
> firewalls, etc). **ARP** solves this: every IPv4 device on your local
> network segment must answer ARP requests to communicate at all, so an ARP
> scan reliably finds nearly 100% of connected devices regardless of
> firewalls. PyNexus automatically uses ARP when available and silently
> falls back to ping/TCP otherwise. To enable ARP scanning:
>
> 1. Install **[Npcap](https://npcap.com/)** (Windows) — during setup, check
>    **"Install Npcap in WinPcap API-compatible mode"**. On Linux, install
>    `libpcap` (`sudo apt install libpcap-dev`); macOS has it built in.
> 2. Make sure `scapy` is installed: `pip install scapy` (already in
>    `requirements.txt`).
> 3. Run PyNexus from an **elevated/Administrator terminal** (Windows) or
>    with `sudo` (Linux/macOS) — raw ARP frames require elevated privileges.
>
> Without Npcap/root, you'll see a `"No libpcap provider available"` warning
> at startup — this is expected and non-fatal; PyNexus just uses the ping
> fallback instead.

### Discover connected devices

```bash
# Auto-detect your local /24 subnet and list everything on it
python main.py discover

# Or specify a subnet explicitly
python main.py discover 192.168.1.0/24

# Save the device list as a report
python main.py discover 192.168.1.0/24 --output html
```

Sample output:

```
            Connected Devices on 192.168.1.0/24 (6/254 responded)
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ IP Address    ┃ Status      ┃ Hostname        ┃ MAC Address       ┃ Vendor         ┃ Latency (ms) ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ 192.168.1.1   │ ONLINE      │ router.home     │ AA:BB:CC:11:22:33 │ Cisco Systems  │         2.10 │
│ 192.168.1.14  │ THIS DEVICE │ DESKTOP-CDU0ABU │ -                 │ -              │         0.42 │
│ 192.168.1.42  │ ONLINE      │ -               │ B8:27:EB:44:55:66 │ Raspberry Pi   │         5.31 │
└───────────────┴─────────────┴─────────────────┴───────────────────┴────────────────┴──────────────┘
```

> **Note on MAC addresses:** MAC lookup reads your OS's ARP cache, which is
> only populated for devices your machine has recently talked to and only
> works for devices on the *same local subnet* (not across routers/VPNs).
> Running `discover` itself (which pings every host) populates the cache, so
> MAC addresses generally show up correctly on the first run. For guaranteed
> MAC visibility on Windows, you can also run `arp -a` yourself right after
> a discover sweep.

### Deep-scan a host

### Deep-scan a host

```bash
python main.py scan <target> [options]
```

`<target>` can be:
- A single IP address: `192.168.1.1`
- A hostname: `scanme.nmap.org`
- A CIDR range: `192.168.1.0/24`

### Scan Options

| Flag | Description | Default |
|---|---|---|
| `--ports SPEC` | `top100`, `top1000`, `all`, or custom e.g. `22,80,1000-1010` | `top100` |
| `--timeout SECONDS` | Per-connection timeout | `1.5` |
| `--threads N` | Max concurrent connections | `200` |
| `--retries N` | Retries per port on timeout | `1` |
| `--udp` | Also scan UDP ports | off |
| `--syn` | Use SYN scan (requires scapy + root/admin) | off (connect scan) |
| `--dns` | Enumerate DNS records | off |
| `--ssl` | Inspect SSL/TLS certificates on relevant open ports | off |
| `--traceroute` | Run traceroute to the target | off |
| `--no-os-detect` | Disable OS fingerprint estimation | (enabled by default) |
| `--no-ping` | Skip host discovery, scan ports directly | off |
| `--output {html,json,csv,xml}` | Generate a report file | none |
| `--output-path PATH` | Custom report file path | auto-generated in `output/` |

---

## Examples

```bash
# Basic scan of a single host, top 100 ports
python main.py scan 192.168.1.1

# Scan a public test target
python main.py scan scanme.nmap.org

# Scan an entire subnet
python main.py scan 192.168.1.0/24

# Custom port range
python main.py scan 192.168.1.1 --ports 1-1000

# Preset port lists
python main.py scan 192.168.1.1 --ports top100
python main.py scan 192.168.1.1 --ports top1000
python main.py scan 192.168.1.1 --ports all

# Timing and concurrency
python main.py scan 192.168.1.1 --timeout 2 --threads 500

# Extra checks
python main.py scan example.com --dns
python main.py scan example.com --ssl
python main.py scan 192.168.1.1 --traceroute

# Report generation
python main.py scan 192.168.1.1 --output html
python main.py scan 192.168.1.1 --output json
python main.py scan 192.168.1.1 --output csv
python main.py scan 192.168.1.1 --output xml
```

---

## Screenshots

> _Add screenshots of your terminal output and HTML report here._

- `assets/screenshot-terminal.png` — Rich terminal UI during a scan (placeholder)
- `assets/screenshot-html-report.png` — Sample HTML report (placeholder)

---

## Troubleshooting

**"scapy is not installed" warnings**
ARP discovery and SYN scanning are optional features. Install scapy
(`pip install scapy`) and run the tool with elevated privileges (root on
Linux/macOS, Administrator on Windows) to enable them. Without scapy, the
tool automatically falls back to ICMP/TCP ping for discovery and full TCP
connect scanning for ports — both work without special privileges.

**All ports show as "filtered"**
This usually means a firewall is dropping packets silently, or your timeout
is too short for the network path. Try increasing `--timeout` (e.g. `--timeout 3`).

**Traceroute returns no hops**
Ensure the `traceroute` (Linux/macOS) or `tracert` (Windows) binary is
installed and available on your `PATH`. Some cloud/container environments
restrict raw ICMP, which can prevent traceroute from working at all.

**DNS enumeration returns empty results**
Install `dnspython` (`pip install dnspython`), and make sure the target
resolves to a real domain name — enumerating DNS records against a bare IP
address without a reverse hostname will not return meaningful results.

**Permission denied on SYN scan**
SYN scanning requires raw socket access, which needs root/Administrator
privileges. Run PyNexus with `sudo` (Linux/macOS) or an elevated terminal
(Windows), or omit `--syn` to use the standard TCP connect scan instead.

**Scan is slow on large ranges**
Increase `--threads` for more concurrency, reduce `--timeout`, or scan a
smaller port range (e.g. `top100` instead of `all`).

---

## FAQ

**Is this a replacement for Nmap?**
No. PyNexus is an educational, extensible Python implementation covering many
of Nmap's core concepts (discovery, port scanning, service/banner detection,
OS estimation, DNS/SSL enumeration, traceroute, reporting). Nmap remains the
industry-standard tool for professional engagements with far more advanced
fingerprinting, NSE scripting, and packet-crafting capabilities.

**Can I use this against any IP address?**
No — only against systems you own or have explicit written authorization to
test. Unauthorized scanning may violate computer misuse laws.

**Why is OS detection labeled an "estimate"?**
PyNexus uses lightweight TTL-based heuristics rather than the full active
packet-crafting fingerprint database that Nmap uses. This is intentionally
simple, fast, and non-intrusive — but far less precise than dedicated OS
fingerprinting tools.

**Does this support IPv6?**
Basic IPv6 literal targets are supported via Python's standard `socket` and
`ipaddress` libraries; some helper utilities (e.g. ARP discovery) are IPv4-only.

**How do I add a new service or vendor to the database?**
Edit `database/services.json` (port → service name) or `database/vendors.json`
(MAC OUI prefix → vendor name). Both are plain JSON files loaded at runtime.

---

## License

This project is provided under the MIT License. See below:

```
MIT License

Copyright (c) 2026 PyNexus Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## Ethical Usage Reminder

Only scan systems and networks you own or are explicitly authorized to test.
This tool is provided for learning, defensive security, and legitimate
network administration. Misuse of this software for unauthorized access or
disruption of computer systems is illegal in most jurisdictions and is not
condoned by the authors.

---

## Credits

**Developer:** anshapi
**Contact:** [t.me/nepalimomoswala](https://t.me/nepalimomoswala)

Issues, feature requests, and pull requests are welcome — open one on the
GitHub repo or reach out directly via Telegram.
