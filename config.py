"""
config.py - Global configuration and constants for PyNexus Scanner.
"""

from __future__ import annotations
import os

APP_NAME = "PyNexus Scanner"
APP_VERSION = "1.0.0"

# Default scan parameters
DEFAULT_TIMEOUT = 1.5          # seconds per connection attempt
DEFAULT_THREADS = 200          # default concurrency
DEFAULT_RETRIES = 1
DEFAULT_TRACEROUTE_HOPS = 30
DEFAULT_TRACEROUTE_TIMEOUT = 1.0

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.join(BASE_DIR, "database")
REPORTS_OUTPUT_DIR = os.path.join(BASE_DIR, "output")

SERVICES_DB_PATH = os.path.join(DATABASE_DIR, "services.json")
VENDORS_DB_PATH = os.path.join(DATABASE_DIR, "vendors.json")

# Top port lists (subset representative of nmap's most common ports)
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6379, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157, 27017, 5985, 5986, 111, 2181,
]

TOP_1000_PORTS = sorted(set(TOP_100_PORTS + list(range(1, 1025)) + [
    1194, 1433, 1521, 1723, 1900, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2375, 2376, 27017, 27018, 3260, 3306, 3389, 3690, 4433, 4444, 4567,
    5000, 5432, 5601, 5672, 5900, 5984, 6000, 6379, 6443, 7000, 7001, 7077,
    7199, 7443, 8000, 8008, 8009, 8080, 8081, 8083, 8086, 8088, 8161, 8200,
    8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999, 10000,
    11211, 15672, 27017, 28017, 50000, 50070, 61616,
]))

ALL_PORTS_RANGE = (1, 65535)

# Common well-known service ports mapping fallback (used if services.json missing)
DEFAULT_SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 194: "irc", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 515: "printer", 587: "smtp-submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2181: "zookeeper", 27017: "mongodb", 27018: "mongodb",
    3128: "squid-proxy", 3306: "mysql", 3389: "rdp", 3690: "svn",
    5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 5985: "winrm-http", 5986: "winrm-https",
    6379: "redis", 6443: "kubernetes-api", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9000: "sonarqube",
    9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch-cluster", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27019: "mongodb-shard", 50070: "hadoop-namenode",
}

# Logging
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_LEVEL = os.environ.get("PYNEXUS_LOG_LEVEL", "INFO")

DISCLAIMER = (
    "PyNexus Scanner is intended for authorized security testing, network "
    "administration, and educational purposes ONLY. Scanning networks or "
    "hosts without explicit permission from the owner may be illegal in "
    "your jurisdiction. The authors assume no liability for misuse."
)
