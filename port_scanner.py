"""
╔══════════════════════════════════════════════════════════════╗
║          OLUWASEYI PORT SCANNER & VULNERABILITY FINDER                                   ║
║   For authorized security testing and network auditing only                         ║
╚══════════════════════════════════════════════════════════════╝

Usage:
   python port_scanner.py -t <target> [options]

Examples:
    python port_scanner.py -t 192.168.1.1
    python port_scanner.py -t 192.168.1.1 -p 1-1000 --vulns
    python port_scanner.py -t 192.168.1.1 -p 22,80,443,8080 --output report.txt
    python port_scanner.py -t 192.168.1.1 --top-ports --threads 100

  WARNING: Only scan systems you own or have explicit written permission to test.
   Unauthorized port scanning may be illegal in your jurisdiction.
"""

import socket
import sys
import argparse
import threading
import time
import json
import re
import ipaddress
import urllib.request
import urllib.error
import ssl
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────
#  CONSTANTS & KNOWN SERVICE BANNERS
# ─────────────────────────────────────────────

VERSION = "1.0.0"

# Top 100 most common ports
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135,
    139, 143, 194, 389, 443, 445, 465, 514, 515,
    587, 631, 993, 995, 1080, 1194, 1433, 1521,
    1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    3000, 3306, 3389, 3724, 4333, 4444, 4899, 5000,
    5432, 5900, 5985, 6379, 6667, 7001, 7002, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200,
    9300, 10000, 11211, 27017, 27018, 28017,
]

# Service name mapping (port -> service)
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    464: "Kerberos", 465: "SMTPS", 500: "IKE/IPsec",
    514: "Syslog", 515: "LPD", 587: "SMTP-Submission",
    631: "IPP/CUPS", 636: "LDAPS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS Proxy",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle DB",
    1723: "PPTP VPN", 2049: "NFS", 2082: "cPanel HTTP",
    2083: "cPanel HTTPS", 2086: "WHM HTTP", 2087: "WHM HTTPS",
    3000: "Dev Server/Grafana", 3306: "MySQL/MariaDB",
    3389: "RDP", 3724: "WoW/Blizzard", 4444: "Metasploit",
    4899: "Radmin", 5000: "Flask/UPnP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 6667: "IRC", 7001: "WebLogic",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter/HTTP-Alt",
    9000: "PHP-FPM/Portainer", 9090: "Cockpit/Prometheus",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    10000: "Webmin", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB-Shard", 28017: "MongoDB-Web",
}

# Banner probes per service (sent to grab version info)
BANNER_PROBES = {
    21:  b"",
    22:  b"",
    23:  b"\r\n",
    25:  b"EHLO scanner\r\n",
    80:  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"",
    143: b"",
    443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    3306: b"",
    5432: b"",
    6379: b"INFO server\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"",
}

# ─────────────────────────────────────────────
#  KNOWN VULNERABILITY DATABASE
#  (offline subset — extend or replace with live NVD API)
# ─────────────────────────────────────────────

VULN_DB = {
    # FTP
    "vsftpd 2.3.4": [
        {"cve": "CVE-2011-2523", "cvss": 10.0, "severity": "CRITICAL",
         "desc": "vsftpd 2.3.4 backdoor — allows remote root shell via smiley ':)' in username",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"}
    ],
    "proftpd 1.3.3": [
        {"cve": "CVE-2010-4221", "cvss": 10.0, "severity": "CRITICAL",
         "desc": "ProFTPD 1.3.3 remote root code execution via Telnet IAC buffer overflow",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2010-4221"}
    ],

    # SSH
    "openssh 7.2": [
        {"cve": "CVE-2016-6210", "cvss": 5.3, "severity": "MEDIUM",
         "desc": "OpenSSH 7.2 user enumeration via timing difference in authentication",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2016-6210"}
    ],
    "openssh 7.4": [
        {"cve": "CVE-2017-15906", "cvss": 5.3, "severity": "MEDIUM",
         "desc": "OpenSSH 7.4 zero-length RSA key creation in read-only mode",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-15906"}
    ],
    "libssh 0.6": [
        {"cve": "CVE-2018-10933", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "libssh 0.6.x authentication bypass — send MSG_USERAUTH_SUCCESS before auth",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-10933"}
    ],

    # HTTP/Apache
    "apache 2.4.49": [
        {"cve": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "Apache 2.4.49 path traversal and RCE (mod_cgi enabled)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "Apache 2.4.49-2.4.50 path traversal bypass (follow-up to CVE-2021-41773)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"}
    ],
    "apache 2.4.50": [
        {"cve": "CVE-2021-42013", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "Apache 2.4.50 path traversal/RCE bypass of CVE-2021-41773 patch",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"}
    ],
    "apache 2.2": [
        {"cve": "CVE-2017-7679", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "Apache 2.2.x mod_mime buffer overread — heap overflow via crafted Content-Type",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-7679"}
    ],

    # nginx
    "nginx 1.16": [
        {"cve": "CVE-2019-20372", "cvss": 5.3, "severity": "MEDIUM",
         "desc": "nginx 1.16 memory disclosure via specially crafted request in error log reading",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-20372"}
    ],

    # IIS
    "iis 6.0": [
        {"cve": "CVE-2017-7269", "cvss": 10.0, "severity": "CRITICAL",
         "desc": "IIS 6.0 WebDAV buffer overflow RCE (ScStoragePathFromUrl)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-7269"}
    ],
    "iis 5.0": [
        {"cve": "CVE-2001-0507", "cvss": 7.5, "severity": "HIGH",
         "desc": "IIS 5.0 .idq/ida ISAPI extension buffer overflow (Code Red worm vector)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2001-0507"}
    ],

    # SMB
    "smb": [
        {"cve": "CVE-2017-0144", "cvss": 9.3, "severity": "CRITICAL",
         "desc": "EternalBlue — SMBv1 RCE exploit (WannaCry/NotPetya ransomware vector)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"},
        {"cve": "CVE-2017-0145", "cvss": 9.3, "severity": "CRITICAL",
         "desc": "EternalChampion — SMBv2 transaction vulnerability RCE",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-0145"},
        {"cve": "CVE-2020-0796", "cvss": 10.0, "severity": "CRITICAL",
         "desc": "SMBGhost — SMBv3 compression RCE/privilege escalation (Windows 10/Server 2019)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796"}
    ],

    # RDP
    "rdp": [
        {"cve": "CVE-2019-0708", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "BlueKeep — RDP pre-auth RCE, no user interaction required (Windows 7/Server 2008)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"},
        {"cve": "CVE-2020-0609", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "Windows RD Gateway pre-auth RCE (Windows Server 2012-2019)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-0609"}
    ],

    # MySQL
    "mysql 5.5": [
        {"cve": "CVE-2016-6662", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "MySQL 5.5 remote root code execution via malicious my.cnf injection",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662"}
    ],
    "mysql 5.6": [
        {"cve": "CVE-2016-6662", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "MySQL 5.6 remote root code execution via malicious my.cnf injection",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662"}
    ],
    "mariadb 10.1": [
        {"cve": "CVE-2016-6662", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "MariaDB 10.1 remote root code execution via malicious my.cnf injection",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2016-6662"}
    ],

    # PostgreSQL
    "postgresql 9.3": [
        {"cve": "CVE-2019-9193", "cvss": 7.2, "severity": "HIGH",
         "desc": "PostgreSQL 9.3 COPY TO/FROM PROGRAM allows arbitrary OS command execution",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-9193"}
    ],

    # Redis
    "redis": [
        {"cve": "CVE-2022-0543", "cvss": 10.0, "severity": "CRITICAL",
         "desc": "Redis Lua sandbox escape — unauthenticated RCE via Lua library injection",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"},
        {"cve": "CVE-2015-8080", "cvss": 7.5, "severity": "HIGH",
         "desc": "Redis integer overflow in Lua allowing sandbox escape",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-8080"}
    ],

    # MongoDB
    "mongodb": [
        {"cve": "CVE-2019-2386", "cvss": 7.1, "severity": "HIGH",
         "desc": "MongoDB after removing a user, failed login attempts with deleted credentials may succeed",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-2386"}
    ],

    # Elasticsearch
    "elasticsearch": [
        {"cve": "CVE-2014-3120", "cvss": 7.5, "severity": "HIGH",
         "desc": "Elasticsearch 1.x dynamic script execution allows arbitrary OS commands",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2014-3120"},
        {"cve": "CVE-2015-1427", "cvss": 10.0, "severity": "CRITICAL",
         "desc": "Elasticsearch Groovy sandbox bypass RCE (ShellShock-style)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2015-1427"}
    ],

    # OpenSSL
    "openssl 1.0.1": [
        {"cve": "CVE-2014-0160", "cvss": 7.5, "severity": "HIGH",
         "desc": "Heartbleed — OpenSSL 1.0.1-1.0.1f TLS heartbeat memory disclosure (64KB per request)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"}
    ],
    "openssl 1.0.2": [
        {"cve": "CVE-2016-0800", "cvss": 5.9, "severity": "MEDIUM",
         "desc": "DROWN — SSL2 padding oracle allows decryption of TLS sessions sharing RSA key",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2016-0800"}
    ],

    # Telnet (generic — service itself is the vulnerability)
    "telnet": [
        {"cve": "CVE-2011-4862", "cvss": 10.0, "severity": "CRITICAL",
         "desc": "Telnet daemon buffer overflow via long encryption key (FreeBSD/Linux)",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2011-4862"},
        {"cve": "INSECURE-PROTOCOL", "cvss": 8.0, "severity": "HIGH",
         "desc": "Telnet transmits credentials and data in plaintext — trivially interceptable",
         "ref": "https://www.iana.org/assignments/service-names-port-numbers/"}
    ],

    # VNC
    "vnc": [
        {"cve": "CVE-2019-15681", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "LibVNCServer memory leak — unauthenticated attacker can steal server memory",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-15681"}
    ],

    # Memcached
    "memcached": [
        {"cve": "CVE-2018-1000115", "cvss": 7.5, "severity": "HIGH",
         "desc": "Memcached exposed UDP port 11211 — used for massive DDoS amplification attacks",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-1000115"}
    ],

    # Webmin
    "webmin": [
        {"cve": "CVE-2019-15107", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "Webmin 1.882-1.921 backdoor — unauthenticated RCE via password_change.cgi",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-15107"}
    ],

    # WebLogic
    "weblogic": [
        {"cve": "CVE-2020-14882", "cvss": 9.8, "severity": "CRITICAL",
         "desc": "Oracle WebLogic Server RCE — unauthenticated via HTTP GET request",
         "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"}
    ],
}

# Port-based generic vulnerability hints (when banner not matched)
PORT_VULN_HINTS = {
    23:    "Telnet is inherently insecure — all traffic including credentials is sent in plaintext",
    139:   "NetBIOS session service — historically exploited (MS08-067, EternalBlue vectors)",
    445:   "SMB — check for EternalBlue (CVE-2017-0144) and SMBGhost (CVE-2020-0796)",
    3389:  "RDP open — check for BlueKeep (CVE-2019-0708) and DejaBlue (CVE-2019-1181/1182)",
    5900:  "VNC open — ensure authentication is required; no-auth VNC is a direct takeover vector",
    6379:  "Redis — if unauthenticated/exposed publicly, full data access and potential RCE",
    9200:  "Elasticsearch — if unauthenticated, full read/write access to all data",
    27017: "MongoDB — if unauthenticated/no auth required, full database access",
    11211: "Memcached UDP/TCP open — DDoS amplification and data exposure risk",
    2049:  "NFS — may expose filesystem shares without authentication",
    4444:  "Port 4444 — commonly used by Metasploit payloads and reverse shells",
    1080:  "SOCKS proxy — if open publicly, may be abused for traffic proxying/anonymization",
}


# ─────────────────────────────────────────────
#  COLORS (terminal output)
# ─────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def severity(s):
        return {
            "CRITICAL": C.RED + C.BOLD,
            "HIGH":     C.RED,
            "MEDIUM":   C.YELLOW,
            "LOW":      C.BLUE,
            "INFO":     C.CYAN,
        }.get(s, C.WHITE)

    @staticmethod
    def cvss(score):
        if score >= 9.0: return C.RED + C.BOLD
        if score >= 7.0: return C.RED
        if score >= 4.0: return C.YELLOW
        return C.GREEN


# ─────────────────────────────────────────────
#  CORE SCANNER CLASS
# ─────────────────────────────────────────────

class PortScanner:

    def __init__(self, target, ports, threads=100, timeout=1.5, grab_banners=True, check_vulns=True):
        self.target       = target
        self.ports        = ports
        self.threads      = threads
        self.timeout      = timeout
        self.grab_banners = grab_banners
        self.check_vulns  = check_vulns
        self.results      = []
        self.start_time   = None
        self.end_time     = None
        self._lock        = threading.Lock()
        self._scanned     = 0
        self._total       = len(ports)

    # ── Resolve hostname ──────────────────────
    def resolve(self):
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve host '{self.target}': {e}")

    # ── TCP connect scan ─────────────────────
    def scan_port(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = ""
                if self.grab_banners:
                    banner = self._grab_banner(sock, port)
                sock.close()
                return {"port": port, "state": "open", "banner": banner}
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None

    # ── Banner / version grabber ──────────────
    def _grab_banner(self, sock, port):
        try:
            probe = BANNER_PROBES.get(port, b"")
            if probe:
                sock.send(probe)
            sock.settimeout(2.0)
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()[:256]
        except Exception:
            return ""

    # ── Parse version from banner ─────────────
    @staticmethod
    def parse_version(port, banner):
        if not banner:
            return SERVICE_MAP.get(port, "unknown"), ""

        service = SERVICE_MAP.get(port, "unknown")
        version = ""

        patterns = [
            # SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            (r"SSH-[\d.]+-(\S+)", lambda m: ("SSH", m.group(1).replace("_", " "))),
            # HTTP Server header
            (r"[Ss]erver:\s*([^\r\n]+)", lambda m: (service, m.group(1).strip())),
            # FTP banners: "220 vsftpd 3.0.3"
            (r"220[- ].*?(vsftpd|proftpd|filezilla)[^\r\n]*", lambda m: ("FTP", m.group(0).split("220")[-1].strip())),
            # MySQL: greeting packet contains version
            (r"(\d+\.\d+\.\d+[-\w]*)", lambda m: (service, m.group(1))),
            # Redis INFO response
            (r"redis_version:([^\r\n]+)", lambda m: ("Redis", m.group(1).strip())),
            # Elasticsearch JSON version
            (r'"number"\s*:\s*"([^"]+)"', lambda m: ("Elasticsearch", m.group(1))),
        ]

        for pattern, extractor in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                try:
                    service, version = extractor(match)
                    break
                except Exception:
                    continue

        return service, version

    # ── Vulnerability lookup ──────────────────
    @staticmethod
    def lookup_vulns(port, service, version, banner):
        found = []
        search_terms = set()

        # Build search terms from service + version info
        v_lower = version.lower()
        s_lower = service.lower()
        b_lower = banner.lower()

        # Extract major.minor version for matching
        ver_match = re.search(r"(\d+\.\d+)", v_lower + " " + b_lower)
        short_ver = ver_match.group(1) if ver_match else ""

        # Build candidate keys
        if short_ver:
            search_terms.add(f"{s_lower} {short_ver}")
        search_terms.add(s_lower)

        # Add port-based keys
        port_service_map = {
            445: "smb", 139: "smb", 3389: "rdp",
            5900: "vnc", 6379: "redis", 9200: "elasticsearch",
            27017: "mongodb", 11211: "memcached", 23: "telnet",
            10000: "webmin", 7001: "weblogic",
        }
        if port in port_service_map:
            search_terms.add(port_service_map[port])

        # Add banner-derived keys
        for key in VULN_DB:
            if key in b_lower or key in v_lower:
                search_terms.add(key)

        # Look up all matching entries
        seen_cves = set()
        for term in search_terms:
            for db_key, vulns in VULN_DB.items():
                if term in db_key or db_key in term:
                    for v in vulns:
                        if v["cve"] not in seen_cves:
                            found.append(v)
                            seen_cves.add(v["cve"])

        # Add port-based hints as INFO-level entries
        if port in PORT_VULN_HINTS and not found:
            found.append({
                "cve": "ADVISORY",
                "cvss": 0.0,
                "severity": "INFO",
                "desc": PORT_VULN_HINTS[port],
                "ref": "https://nvd.nist.gov"
            })

        # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        found.sort(key=lambda x: (order.get(x["severity"], 9), -x["cvss"]))
        return found

    # ── Query NVD API (online CVE enrichment) ─
    @staticmethod
    def query_nvd(keyword, max_results=5):
        """Query NIST NVD API for CVEs related to a keyword/service."""
        try:
            keyword_enc = urllib.parse.quote(keyword)
            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={keyword_enc}&resultsPerPage={max_results}"
            )
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "PortScanner/1.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                results = []
                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    cve_id   = cve_data.get("id", "N/A")
                    desc     = next(
                        (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
                        "No description"
                    )[:120]
                    metrics  = cve_data.get("metrics", {})
                    cvss_v3  = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                    score    = 0.0
                    severity = "UNKNOWN"
                    if cvss_v3:
                        score    = cvss_v3[0]["cvssData"]["baseScore"]
                        severity = cvss_v3[0]["cvssData"]["baseSeverity"]
                    results.append({
                        "cve": cve_id,
                        "cvss": score,
                        "severity": severity,
                        "desc": desc,
                        "ref": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
                return results
        except Exception:
            return []

    # ── Progress bar ──────────────────────────
    def _print_progress(self):
        with self._lock:
            self._scanned += 1
            pct = int((self._scanned / self._total) * 40)
            bar = "█" * pct + "░" * (40 - pct)
            print(f"\r  {C.DIM}[{bar}] {self._scanned}/{self._total}{C.RESET}", end="", flush=True)

    # ── Main scan runner ──────────────────────
    def run(self):
        print(f"\n{C.CYAN}{'═'*62}{C.RESET}")
        print(f"{C.BOLD}  ONYX PORT SCANNER v{VERSION}{C.RESET}")
        print(f"{C.CYAN}{'═'*62}{C.RESET}")

        # Resolve target
        try:
            ip = self.resolve()
        except ValueError as e:
            print(f"\n{C.RED}[ERROR]{C.RESET} {e}")
            sys.exit(1)

        if ip != self.target:
            print(f"\n  {C.BOLD}Target  :{C.RESET} {self.target} ({C.CYAN}{ip}{C.RESET})")
        else:
            print(f"\n  {C.BOLD}Target  :{C.RESET} {C.CYAN}{ip}{C.RESET}")

        print(f"  {C.BOLD}Ports   :{C.RESET} {len(self.ports)} ports")
        print(f"  {C.BOLD}Threads :{C.RESET} {self.threads}")
        print(f"  {C.BOLD}Timeout :{C.RESET} {self.timeout}s")
        print(f"  {C.BOLD}Time    :{C.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{C.CYAN}{'─'*62}{C.RESET}")
        print(f"  {C.DIM}Scanning...{C.RESET}")

        self.start_time = time.time()
        open_ports = []

        # Threaded scan
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port for port in self.ports}
            for future in as_completed(futures):
                self._print_progress()
                result = future.result()
                if result:
                    open_ports.append(result)

        self.end_time = time.time()
        elapsed = self.end_time - self.start_time
        print(f"\r  {C.GREEN}Scan complete{C.RESET} — {elapsed:.2f}s{' ' * 20}")

        if not open_ports:
            print(f"\n  {C.YELLOW}No open ports found.{C.RESET}\n")
            return []

        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])

        print(f"\n{C.CYAN}{'─'*62}{C.RESET}")
        print(f"  {C.BOLD}{'PORT':<10}{'STATE':<10}{'SERVICE':<20}{'VERSION'}{C.RESET}")
        print(f"{C.CYAN}{'─'*62}{C.RESET}")

        for entry in open_ports:
            port   = entry["port"]
            banner = entry["banner"]
            service, version = self.parse_version(port, banner)
            entry["service"] = service
            entry["version"] = version

            # Version detection output
            version_display = version if version else C.DIM + "unknown" + C.RESET
            print(f"  {C.GREEN}{port:<10}{C.RESET}{'open':<10}{C.CYAN}{service:<20}{C.RESET}{version_display}")

            if banner and banner != version:
                banner_short = banner[:60].replace('\n', ' ').replace('\r', '')
                print(f"  {C.DIM}{'':10}{'':10}Banner: {banner_short}{C.RESET}")

            # Vulnerability lookup
            if self.check_vulns:
                vulns = self.lookup_vulns(port, service, version, banner)
                entry["vulnerabilities"] = vulns

                if vulns:
                    for v in vulns:
                        sev_color = C.severity(v["severity"])
                        cvss_color = C.cvss(v["cvss"])
                        cvss_str = f"CVSS {v['cvss']:.1f}" if v["cvss"] > 0 else "ADVISORY"
                        print(f"  {C.DIM}{'':10}{'':10}{C.RESET}"
                              f"{sev_color}[{v['severity']}]{C.RESET} "
                              f"{cvss_color}{cvss_str}{C.RESET} "
                              f"{C.BOLD}{v['cve']}{C.RESET}")
                        print(f"  {'':10}{'':10}{C.DIM}{v['desc'][:65]}{C.RESET}")
                else:
                    entry["vulnerabilities"] = []

            print()

        self.results = open_ports
        self._print_summary(open_ports, elapsed)
        return open_ports

    # ── Summary ───────────────────────────────
    def _print_summary(self, open_ports, elapsed):
        total_vulns = sum(len(p.get("vulnerabilities", [])) for p in open_ports)
        critical    = sum(1 for p in open_ports for v in p.get("vulnerabilities", []) if v["severity"] == "CRITICAL")
        high        = sum(1 for p in open_ports for v in p.get("vulnerabilities", []) if v["severity"] == "HIGH")
        medium      = sum(1 for p in open_ports for v in p.get("vulnerabilities", []) if v["severity"] == "MEDIUM")

        print(f"{C.CYAN}{'═'*62}{C.RESET}")
        print(f"  {C.BOLD}SCAN SUMMARY{C.RESET}")
        print(f"{C.CYAN}{'─'*62}{C.RESET}")
        print(f"  Open ports found  : {C.GREEN}{C.BOLD}{len(open_ports)}{C.RESET}")
        print(f"  Total CVEs found  : {C.BOLD}{total_vulns}{C.RESET}")
        if critical: print(f"  ├─ CRITICAL       : {C.RED+C.BOLD}{critical}{C.RESET}")
        if high:     print(f"  ├─ HIGH           : {C.RED}{high}{C.RESET}")
        if medium:   print(f"  └─ MEDIUM         : {C.YELLOW}{medium}{C.RESET}")
        print(f"  Scan duration     : {elapsed:.2f}s")
        print(f"{C.CYAN}{'═'*62}{C.RESET}\n")


# ─────────────────────────────────────────────
#  OUTPUT / REPORTING
# ─────────────────────────────────────────────

def save_report(results, target, output_path):
    lines = [
        "=" * 62,
        f"  ONYX PORT SCANNER — Vulnerability Report",
        f"  Target : {target}",
        f"  Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 62, ""
    ]
    for entry in results:
        port    = entry["port"]
        service = entry.get("service", "unknown")
        version = entry.get("version", "")
        vulns   = entry.get("vulnerabilities", [])
        lines.append(f"PORT {port}/tcp — {service} {version}")
        if entry.get("banner"):
            lines.append(f"  Banner : {entry['banner'][:80]}")
        if vulns:
            lines.append("  Vulnerabilities:")
            for v in vulns:
                cvss_str = f"CVSS {v['cvss']:.1f}" if v["cvss"] > 0 else "ADVISORY"
                lines.append(f"    [{v['severity']}] {cvss_str} {v['cve']}")
                lines.append(f"    {v['desc']}")
                lines.append(f"    Ref: {v['ref']}")
                lines.append("")
        else:
            lines.append("  No known vulnerabilities matched.\n")
        lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    print(f"  {C.GREEN}✓{C.RESET} Report saved to: {C.BOLD}{output_path}{C.RESET}\n")


def save_json(results, target, output_path):
    data = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "open_ports": results
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  {C.GREEN}✓{C.RESET} JSON saved to: {C.BOLD}{output_path}{C.RESET}\n")


# ─────────────────────────────────────────────
#  ARGUMENT PARSING
# ─────────────────────────────────────────────

def parse_ports(port_arg):
    """Parse port argument: '80', '1-1000', '22,80,443', 'top'"""
    ports = set()
    if not port_arg or port_arg.lower() == "top":
        return TOP_PORTS
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def validate_target(target):
    """Allow hostname or IP address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Hostname — basic validation
        return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$", target))


def main():
    import urllib.parse  # needed for NVD query

    parser = argparse.ArgumentParser(
        description="ONYX Port Scanner — Open port, version detection & vulnerability finder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t 192.168.1.1
  python port_scanner.py -t 192.168.1.1 -p 1-1000
  python port_scanner.py -t 192.168.1.1 -p 22,80,443,3306,3389
  python port_scanner.py -t 192.168.1.1 --top-ports --threads 200
  python port_scanner.py -t 192.168.1.1 --output report.txt --json results.json
  python port_scanner.py -t myserver.local -p 1-65535 --timeout 2

⚠  Only scan systems you own or have explicit written permission to test.
        """
    )
    parser.add_argument("-t", "--target",    required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports",     default=None,  help="Ports: '80', '1-1000', '22,80,443' (default: top ports)")
    parser.add_argument("--top-ports",       action="store_true", help="Scan top 100 common ports (default if -p omitted)")
    parser.add_argument("--full",            action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--threads",         type=int, default=100, help="Concurrent threads (default: 100)")
    parser.add_argument("--timeout",         type=float, default=1.5, help="Connection timeout in seconds (default: 1.5)")
    parser.add_argument("--no-banner",       action="store_true", help="Skip banner/version grabbing")
    parser.add_argument("--no-vulns",        action="store_true", help="Skip vulnerability lookup")
    parser.add_argument("--output",          help="Save text report to file")
    parser.add_argument("--json",            help="Save JSON results to file")

    args = parser.parse_args()

    # ── Legal warning ──────────────────────────
    print(f"""
{C.YELLOW}{'─'*62}
  ⚠  LEGAL NOTICE
  This tool is for authorized security testing only.
  You must have explicit written permission to scan
  any target you do not personally own.
  Unauthorized scanning may violate computer crime laws.
{'─'*62}{C.RESET}""")
    confirm = input("  I confirm I have permission to scan this target [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        print(f"\n{C.RED}  Aborted.{C.RESET}\n")
        sys.exit(0)

    # ── Validate target ────────────────────────
    if not validate_target(args.target):
        print(f"\n{C.RED}[ERROR]{C.RESET} Invalid target: {args.target}\n")
        sys.exit(1)

    # ── Determine port list ────────────────────
    if args.full:
        ports = list(range(1, 65536))
        print(f"\n  {C.YELLOW}Full scan: 65535 ports — this may take several minutes.{C.RESET}")
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            print(f"\n{C.RED}[ERROR]{C.RESET} Invalid port specification: {e}\n")
            sys.exit(1)
    else:
        ports = TOP_PORTS

    # ── Run scanner ────────────────────────────
    scanner = PortScanner(
        target       = args.target,
        ports        = ports,
        threads      = args.threads,
        timeout      = args.timeout,
        grab_banners = not args.no_banner,
        check_vulns  = not args.no_vulns,
    )

    results = scanner.run()

    # ── Save outputs ───────────────────────────
    if args.output and results:
        save_report(results, args.target, args.output)

    if args.json and results:
        save_json(results, args.target, args.json)


if __name__ == "__main__":
    main()
