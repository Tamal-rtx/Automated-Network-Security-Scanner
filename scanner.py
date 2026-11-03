#!/usr/bin/env python3
"""
================================================================================
 Automated Network Security Scanner & Port Mapper (NetScan Sentinel)
================================================================================
 An enterprise-grade, native Python network audit utility designed to inspect
 host endpoints and subnets, discover open TCP ports, extract service banners,
 evaluate security posture using a risk matrix, and generate dual reports
 (human-readable Terminal Markdown & machine-readable JSON).

 Technical Highlights:
   - Zero External Dependencies: Pure Python 3.8+ standard library.
   - High Concurrency: ThreadPoolExecutor with dynamic task balancing.
   - Socket Hardening: Precise socket timeouts, socket recycling, and non-blocking I/O.
   - Risk Taxonomy: High/Medium/Low evaluation based on network hygiene standards.
   - Banner Grabbing: Non-intrusive protocol probes with banner sanitization.
   - Graceful Cancellation: Clean interrupt handling (SIGINT / Ctrl+C).
================================================================================
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Generator, List, Optional, Tuple

# ============================================================================
# RISK TAXONOMY & PORT KNOWLEDGE BASE
# ============================================================================

# Schema: port -> (Service Name, Risk Level [High|Medium|Low|Info], Description, Recommendation)
PORT_KNOWLEDGE_BASE: Dict[int, Tuple[str, str, str, str]] = {
    21: (
        "FTP",
        "Medium",
        "Unencrypted file transfer protocol with plaintext authentication.",
        "Migrate to SFTP (SSH File Transfer) or FTPS with enforced TLS.",
    ),
    22: (
        "SSH",
        "Low",
        "Encrypted remote administration service.",
        "Ensure root login is disabled and enforce public-key authentication.",
    ),
    23: (
        "Telnet",
        "High",
        "Insecure cleartext remote terminal. Credentials and traffic exposed in transit.",
        "Decommission immediately. Transition all administrative sessions to SSH.",
    ),
    25: (
        "SMTP",
        "Medium",
        "Mail transport protocol. Potential relay abuse or cleartext message flow.",
        "Enforce STARTTLS, restrict open relays, and configure SPF/DKIM/DMARC.",
    ),
    53: (
        "DNS",
        "Low",
        "Domain Name System resolver/nameserver.",
        "Restrict open recursion to prevent DNS amplification; disable zone transfers.",
    ),
    69: (
        "TFTP",
        "High",
        "Trivial File Transfer Protocol lacks authentication and encryption.",
        "Disable unless strictly required for isolated PXE booting environments.",
    ),
    80: (
        "HTTP",
        "Medium",
        "Unencrypted web server traffic.",
        "Implement automatic 301/308 redirect to HTTPS and enforce HSTS headers.",
    ),
    110: (
        "POP3",
        "Medium",
        "Cleartext mail delivery protocol.",
        "Transition to POP3 over TLS (POP3S) on port 995.",
    ),
    111: (
        "RPCBind",
        "High",
        "Remote Procedure Call portmapper exposed.",
        "Block external ingress via perimeter firewall; restrict to internal cluster.",
    ),
    135: (
        "MS-RPC",
        "High",
        "Microsoft Windows RPC Endpoint Mapper.",
        "Isolate behind firewalls; block from public internet to prevent enumeration.",
    ),
    139: (
        "NetBIOS",
        "High",
        "NetBIOS Session Service legacy file/printer sharing.",
        "Disable NetBIOS over TCP/IP across untrusted network interfaces.",
    ),
    143: (
        "IMAP",
        "Medium",
        "Unencrypted Internet Message Access Protocol.",
        "Upgrade to IMAPS (IMAP over TLS) on port 993.",
    ),
    389: (
        "LDAP",
        "Medium",
        "Unencrypted Lightweight Directory Access Protocol.",
        "Enforce LDAPS (port 636) or StartTLS to prevent credential interception.",
    ),
    443: (
        "HTTPS",
        "Low",
        "Standard TLS-encrypted web service.",
        "Verify certificate validity and deprecate legacy protocols (TLS 1.0/1.1).",
    ),
    445: (
        "SMB",
        "High",
        "Server Message Block file sharing exposed.",
        "Block port 445 at edge firewalls; enforce SMB signing and encryption.",
    ),
    1433: (
        "MS-SQL",
        "High",
        "Microsoft SQL Server database listener exposed.",
        "Never expose database engines directly to external networks; use VPN/bastion.",
    ),
    1521: (
        "Oracle DB",
        "High",
        "Oracle Database TNS listener exposed.",
        "Isolate database listener within dedicated internal database subnet.",
    ),
    2049: (
        "NFS",
        "High",
        "Network File System exposed without network perimeter protection.",
        "Restrict exports strictly by IP; use Kerberos authentication where available.",
    ),
    3306: (
        "MySQL",
        "High",
        "MySQL relational database listener exposed.",
        "Bind service to 127.0.0.1 or private VPC subnet; enforce TLS connections.",
    ),
    3389: (
        "RDP",
        "High",
        "Remote Desktop Protocol service directly reachable.",
        "Enforce Network Level Authentication (NLA), place behind VPN, require MFA.",
    ),
    5432: (
        "PostgreSQL",
        "High",
        "PostgreSQL database engine port exposed.",
        "Restrict host-based authentication (pg_hba.conf) and avoid public exposure.",
    ),
    5900: (
        "VNC",
        "High",
        "Virtual Network Computing graphical desktop sharing.",
        "Tunnel VNC over SSH or VPN; avoid exposing raw VNC authentication.",
    ),
    6379: (
        "Redis",
        "High",
        "In-memory data store exposed; often unauthenticated by default.",
        "Bind to localhost, require strong AUTH password, or use protected mode.",
    ),
    8080: (
        "HTTP-Alt",
        "Low",
        "Alternate HTTP / application management dashboard.",
        "Verify authentication controls and enforce HTTPS encryption.",
    ),
    8443: (
        "HTTPS-Alt",
        "Low",
        "Alternate HTTPS application or administrative portal.",
        "Ensure administrative portals are protected with multi-factor authentication.",
    ),
    9200: (
        "Elasticsearch",
        "High",
        "Elasticsearch REST interface exposed.",
        "Enforce cluster authentication, role-based access control, and TLS.",
    ),
    27017: (
        "MongoDB",
        "High",
        "MongoDB NoSQL database engine exposed.",
        "Enforce authentication, bind to internal interface, disable default test roles.",
    ),
}

DEFAULT_PORTS = sorted(list(PORT_KNOWLEDGE_BASE.keys()))


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class PortFinding:
    target_host: str
    ip_address: str
    port: int
    service: str
    banner: str
    risk_level: str
    risk_summary: str
    recommendation: str
    latency_ms: float

    def to_dict(self) -> dict:
        return asdict(self)


class ScanMetrics:
    """Thread-safe telemetry and progress tracker."""

    def __init__(self, total_probes: int):
        self._lock = threading.Lock()
        self.total_probes = total_probes
        self.completed_probes = 0
        self.open_ports_found = 0
        self.start_time = time.time()

    def record_probe(self, is_open: bool) -> Tuple[int, int]:
        with self._lock:
            self.completed_probes += 1
            if is_open:
                self.open_ports_found += 1
            return self.completed_probes, self.open_ports_found

    def get_progress_pct(self) -> float:
        with self._lock:
            if self.total_probes == 0:
                return 100.0
            return (self.completed_probes / self.total_probes) * 100.0


# ============================================================================
# INPUT PARSING & TARGET RESOLUTION
# ============================================================================

def resolve_target(target_input: str) -> List[Tuple[str, str]]:
    """
    Parses a target string into a list of (display_label, ip_address) pairs.
    Supports:
      - Single IPv4/IPv6 address: '192.168.1.1'
      - CIDR subnet range: '192.168.1.0/28'
      - Hostname: 'localhost', 'scanme.nmap.org'
    """
    target_input = target_input.strip()
    if not target_input:
        raise ValueError("Target input cannot be empty.")

    # 1. CIDR notation handling
    if "/" in target_input:
        try:
            network = ipaddress.ip_network(target_input, strict=False)
            if network.num_addresses > 1024:
                raise ValueError(
                    f"Subnet '{target_input}' contains {network.num_addresses} hosts. "
                    "To prevent resource exhaustion, please limit subnet scans to /22 (1024 hosts) or smaller."
                )
            hosts = list(network.hosts())
            if not hosts:
                # Handle single-host subnets (/32 for IPv4 or /128 for IPv6)
                hosts = [network.network_address]
            return [(str(ip), str(ip)) for ip in hosts]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation '{target_input}': {e}") from e

    # 2. Single IP address validation
    try:
        ip_obj = ipaddress.ip_address(target_input)
        return [(str(ip_obj), str(ip_obj))]
    except ValueError:
        pass

    # 3. Hostname DNS resolution
    try:
        resolved_ip = socket.gethostbyname(target_input)
        return [(target_input, resolved_ip)]
    except socket.gaierror as e:
        raise ValueError(f"Failed to resolve hostname '{target_input}': {e}") from e


def parse_port_selection(ports_input: Optional[str]) -> List[int]:
    """
    Parses user port specification into a sorted, unique list of integers.
    Supports:
      - None or 'default' -> curated high-value security ports
      - 'all'             -> 1-65535
      - Comma-delimited   -> '80,443,8080'
      - Port ranges       -> '1-1024'
      - Combinations      -> '21-25,80,443,8000-8080'
    """
    if not ports_input or ports_input.strip().lower() == "default":
        return list(DEFAULT_PORTS)

    ports_input = ports_input.strip().lower()
    if ports_input == "all":
        return list(range(1, 65536))

    selected_ports = set()
    tokens = ports_input.split(",")

    for token in tokens:
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range specification: '{token}'")
            try:
                start_p, end_p = int(parts[0]), int(parts[1])
            except ValueError as e:
                raise ValueError(f"Non-integer value in port range: '{token}'") from e

            if start_p > end_p:
                start_p, end_p = end_p, start_p
            if start_p < 1 or end_p > 65535:
                raise ValueError(f"Port range {start_p}-{end_p} outside valid limits (1-65535).")

            selected_ports.update(range(start_p, end_p + 1))
        else:
            try:
                p = int(token)
            except ValueError as e:
                raise ValueError(f"Invalid port number: '{token}'") from e

            if p < 1 or p > 65535:
                raise ValueError(f"Port {p} outside valid limits (1-65535).")
            selected_ports.add(p)

    if not selected_ports:
        raise ValueError("No valid ports specified.")

    return sorted(list(selected_ports))


# ============================================================================
# BANNER EXTRACTION & SANITIZATION ENGINE
# ============================================================================

def sanitize_banner_text(raw_bytes: bytes, max_len: int = 120) -> str:
    """Sanitizes raw socket output into safe, printable single-line ASCII text."""
    if not raw_bytes:
        return "No banner returned"

    # Decode with substitution to prevent decode crashes on raw binary protocols
    text = raw_bytes.decode("ascii", errors="replace").strip()

    # Extract status line or Server header for HTTP responses
    if text.startswith("HTTP/"):
        lines = [ln.strip() for ln in text.split("\r\n") if ln.strip()]
        server_line = next((ln for ln in lines if ln.lower().startswith("server:")), "")
        if server_line:
            text = f"{lines[0]} | {server_line}"
        elif lines:
            text = lines[0]

    # Normalize whitespace, strip control characters
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = re.sub(r"[^\x20-\x7E]", "", text).strip()

    if not text:
        return "Binary response (unprintable)"

    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def extract_banner_from_socket(sock: socket.socket, ip: str, port: int, timeout: float) -> str:
    """
    Extracts service banners using an already connected TCP socket.
    Employs passive banner observation first, followed by safe active probing.
    """
    # 1. TLS-Encrypted Services (HTTPS / SMTPS / FTPS)
    if port in (443, 8443):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                tls_sock.settimeout(timeout)
                probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScan-Sentinel/1.0\r\n\r\n".encode()
                tls_sock.sendall(probe)
                raw_data = tls_sock.recv(1024)
                return sanitize_banner_text(raw_data)
        except Exception:
            return "TLS Service (Active banner query timed out)"

    # 2. Plaintext Services
    try:
        # Step A: Passive Read (FTP, SSH, SMTP, POP3 emit greetings immediately upon connect)
        sock.settimeout(min(timeout, 0.7))
        try:
            greeting = sock.recv(1024)
            if greeting:
                return sanitize_banner_text(greeting)
        except (socket.timeout, socket.error):
            pass

        # Step B: Active Protocol Probe
        sock.settimeout(timeout)
        if port in (80, 8080, 8000, 8888, 5000, 3000):
            payload = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScan-Sentinel/1.0\r\n\r\n".encode()
        else:
            payload = b"\r\n\r\n"

        try:
            sock.sendall(payload)
            response = sock.recv(1024)
            if response:
                return sanitize_banner_text(response)
        except socket.error:
            pass

        return "Service active (no banner advertised)"
    except Exception as exc:
        return f"Banner grab error: {type(exc).__name__}"


# ============================================================================
# AUDIT WORKER
# ============================================================================

def audit_port_endpoint(
    target_host: str,
    ip: str,
    port: int,
    timeout: float,
    grab_banners: bool,
) -> Optional[PortFinding]:
    """
    Audits a single IP:Port endpoint. Returns a PortFinding if open, else None.
    Handles socket initialization, non-blocking connection checks, and error boundaries.
    """
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # connect_ex returns 0 on successful TCP 3-way handshake
        return_code = sock.connect_ex((ip, port))
        latency = (time.perf_counter() - start_time) * 1000.0

        if return_code == 0:
            # Query risk knowledge base
            kb_entry = PORT_KNOWLEDGE_BASE.get(port)
            if kb_entry:
                service, risk_level, risk_desc, recommendation = kb_entry
            else:
                service = "Unknown"
                risk_level = "Medium" if port < 1024 else "Info"
                risk_desc = "Unmapped network service active on host."
                recommendation = "Verify service necessity and enforce perimeter/local firewall rules."

            # Perform banner grabbing if enabled
            if grab_banners:
                banner = extract_banner_from_socket(sock, ip, port, timeout)
            else:
                banner = "Banner extraction skipped"

            return PortFinding(
                target_host=target_host,
                ip_address=ip,
                port=port,
                service=service,
                banner=banner,
                risk_level=risk_level,
                risk_summary=risk_desc,
                recommendation=recommendation,
                latency_ms=round(latency, 2),
            )
        return None

    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except OSError:
        # Handles host unreachable, network down, permission errors
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ============================================================================
# ORCHESTRATION & CONCURRENCY
# ============================================================================

def run_security_audit(
    targets: List[Tuple[str, str]],
    ports: List[int],
    concurrency_limit: int = 50,
    socket_timeout: float = 1.5,
    enable_banners: bool = True,
    verbose: bool = False,
) -> List[PortFinding]:
    """
    Manages concurrent thread pool execution across all target/port combinations.
    Includes thread-safe progress reporting and graceful cancellation.
    """
    total_probes = len(targets) * len(ports)
    metrics = ScanMetrics(total_probes)
    findings: List[PortFinding] = []
    print_lock = threading.Lock()

    print(f"[*] Initializing scan pipeline:")
    print(f"    - Target Entities:   {len(targets)}")
    print(f"    - Ports per Target:  {len(ports)}")
    print(f"    - Total Operations:  {total_probes}")
    print(f"    - Concurrency Limit: {concurrency_limit} worker threads")
    print(f"    - Socket Timeout:    {socket_timeout:.2f}s")
    print(f"    - Banner Inspection: {'Enabled' if enable_banners else 'Disabled'}")
    print("-" * 78)

    def task_generator() -> Generator[Tuple[str, str, int], None, None]:
        for host, ip in targets:
            for port in ports:
                yield (host, ip, port)

    interrupted = False
    with ThreadPoolExecutor(max_workers=concurrency_limit) as executor:
        future_map = {
            executor.submit(audit_port_endpoint, host, ip, p, socket_timeout, enable_banners): (host, ip, p)
            for host, ip, p in task_generator()
        }

        try:
            for future in as_completed(future_map):
                host, ip, p = future_map[future]
                try:
                    finding = future.result()
                    is_open = finding is not None
                    completed, open_count = metrics.record_probe(is_open)

                    if finding:
                        findings.append(finding)
                        with print_lock:
                            badge = f"[{finding.risk_level.upper()}]"
                            print(
                                f" [+] Found OPEN: {finding.ip_address}:{finding.port:<5} "
                                f"| {finding.service:<12} | {badge:<8} | Latency: {finding.latency_ms:.1f}ms"
                            )
                    elif verbose:
                        with print_lock:
                            print(f" [-] Closed: {ip}:{p}")

                    # Real-time console progress update
                    if sys.stdout.isatty():
                        pct = (completed / total_probes) * 100.0
                        sys.stdout.write(
                            f"\rProgress: [{completed}/{total_probes}] ({pct:5.1f}%) | "
                            f"Open Endpoints: {open_count}  "
                        )
                        sys.stdout.flush()

                except Exception as task_err:
                    if verbose:
                        with print_lock:
                            print(f" [!] Task Error ({ip}:{p}): {task_err}")

        except KeyboardInterrupt:
            interrupted = True
            print("\n\n[!] Warning: Interrupt signal received (Ctrl+C). Terminating scan workers...")
            if hasattr(executor, "shutdown"):
                executor.shutdown(wait=False, cancel_futures=True)

    if sys.stdout.isatty():
        sys.stdout.write("\n")

    if interrupted:
        print("[!] Execution stopped by operator. Returning collected findings...")

    # Sort results deterministically by IP and Port
    findings.sort(key=lambda x: (x.ip_address, x.port))
    return findings


# ============================================================================
# REPORTING GENERATORS (MARKDOWN & JSON)
# ============================================================================

def format_markdown_table(findings: List[PortFinding]) -> str:
    """Formats scan results into a clean GitHub-style Markdown table."""
    if not findings:
        return "_No open endpoints discovered._\n"

    headers = ["Target IP", "Port", "Service", "Risk Level", "Banner / Info", "Recommendation"]
    rows = []
    for f in findings:
        clean_rec = f.recommendation.replace("|", "/")
        clean_banner = f.banner.replace("|", "/")
        rows.append([
            f.ip_address,
            str(f.port),
            f.service,
            f.risk_level,
            clean_banner,
            clean_rec,
        ])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    header_line = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"
    separator_line = "| " + " | ".join("-" * col_widths[i] for i in range(len(headers))) + " |"
    data_lines = [
        "| " + " | ".join(row[i].ljust(col_widths[i]) for i in range(len(headers))) + " |"
        for row in rows
    ]

    return "\n".join([header_line, separator_line] + data_lines) + "\n"


def display_console_report(
    target_spec: str,
    total_targets: int,
    ports_scanned: int,
    duration: float,
    findings: List[PortFinding],
) -> None:
    """Renders a comprehensive terminal security audit report."""
    high_count = sum(1 for f in findings if f.risk_level.lower() == "high")
    med_count = sum(1 for f in findings if f.risk_level.lower() == "medium")
    low_count = sum(1 for f in findings if f.risk_level.lower() == "low")
    info_count = sum(1 for f in findings if f.risk_level.lower() == "info")

    print("\n" + "=" * 80)
    print("                     NETWORK SECURITY AUDIT SUMMARY REPORT")
    print("=" * 80)
    print(f" Execution Timestamp:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Target Specification: {target_spec} ({total_targets} host(s))")
    print(f" Ports Scanned/Host:   {ports_scanned}")
    print(f" Total Scan Duration:  {duration:.2f} seconds")
    print(f" Total Endpoints Open: {len(findings)}")
    print("-" * 80)
    print(" RISK EXPOSURE PROFILE:")
    print(f"   - HIGH Risk:   {high_count:<3} {'(Action Required: Insecure or high-risk administrative services detected)' if high_count else ''}")
    print(f"   - MEDIUM Risk: {med_count:<3} {'(Review cleartext protocols and TLS configurations)' if med_count else ''}")
    print(f"   - LOW Risk:    {low_count:<3}")
    print(f"   - INFO:        {info_count:<3}")
    print("=" * 80)
    print("\n### DETAILED FINDINGS TABLE\n")
    print(format_markdown_table(findings))


def export_json_report(
    output_path: str,
    target_spec: str,
    total_targets: int,
    ports: List[int],
    duration: float,
    concurrency: int,
    timeout: float,
    findings: List[PortFinding],
) -> str:
    """Exports findings to a structured JSON file."""
    high_count = sum(1 for f in findings if f.risk_level.lower() == "high")
    med_count = sum(1 for f in findings if f.risk_level.lower() == "medium")
    low_count = sum(1 for f in findings if f.risk_level.lower() == "low")
    info_count = sum(1 for f in findings if f.risk_level.lower() == "info")

    report_payload = {
        "metadata": {
            "scanner": "NetScan Sentinel - Automated Network Security Scanner",
            "version": "1.0.0",
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_input": target_spec,
            "resolved_targets_count": total_targets,
            "ports_scanned_count": len(ports),
            "concurrency_limit": concurrency,
            "socket_timeout_seconds": timeout,
            "scan_duration_seconds": round(duration, 3),
        },
        "summary": {
            "total_open_ports": len(findings),
            "risk_distribution": {
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "info": info_count,
            },
        },
        "findings": [f.to_dict() for f in findings],
    }

    try:
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as json_file:
            json.dump(report_payload, json_file, indent=2)
        return output_path
    except OSError as err:
        print(f"[!] Error saving JSON report to '{output_path}': {err}")
        return ""


# ============================================================================
# CLI ENTRYPOINT
# ============================================================================

def build_cli_parser() -> argparse.ArgumentParser:
    """Builds the command-line argument parser with full configuration options."""
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Automated Network Security Scanner & Port Mapper (Enterprise Grade).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  # Audit localhost using default risk-mapped ports:
  python scanner.py --target 127.0.0.1

  # Audit a remote host with port list and custom thread count:
  python scanner.py --target 192.168.1.10 --ports 21,22,80,443,3306,8080 --threads 100

  # Audit a port range on a hostname with custom JSON report output:
  python scanner.py --target scanme.nmap.org --ports 1-1000 --output report.json

  # Audit a local Class C subnet (/28) with fast 0.8s timeout:
  python scanner.py --target 192.168.1.0/28 --timeout 0.8 --threads 75
        """,
    )

    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="Target IP address, hostname, or CIDR network range (e.g. 192.168.1.1, example.com, 10.0.0.0/28)",
    )
    parser.add_argument(
        "-p", "--ports",
        dest="ports",
        default="default",
        help="Ports to audit: 'default' (common ports), 'all' (1-65535), or comma/range string (e.g. '80,443', '1-1024')",
    )
    parser.add_argument(
        "-w", "--threads",
        dest="threads",
        type=int,
        default=50,
        help="Maximum concurrent worker threads in pool (default: 50, recommended range: 10-200)",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=1.5,
        help="TCP connection timeout in seconds (default: 1.5s)",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        default=None,
        help="Output filepath for structured JSON report (default: scan_report_<timestamp>.json)",
    )
    parser.add_argument(
        "--no-banner",
        dest="no_banner",
        action="store_true",
        help="Disable banner grabbing for high-speed discovery scans",
    )
    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose output showing closed/filtered ports",
    )

    return parser


def main() -> None:
    """Application controller and entry point."""
    parser = build_cli_parser()
    args = parser.parse_args()

    print("=" * 78)
    print(" NetScan Sentinel - Automated Network Security Scanner & Port Mapper")
    print(" Pure Standard Library | Multi-Threaded Engine | Risk Categorization")
    print("=" * 78)

    # 1. Validate & Parse Targets
    try:
        targets = resolve_target(args.target)
    except ValueError as val_err:
        print(f"[!] Error resolving target specification: {val_err}")
        sys.exit(1)

    # 2. Validate & Parse Ports
    try:
        ports = parse_port_selection(args.ports)
    except ValueError as val_err:
        print(f"[!] Error parsing port selection: {val_err}")
        sys.exit(1)

    # 3. Validate Concurrency & Timeout
    threads = max(1, min(args.threads, 500))
    timeout = max(0.2, min(args.timeout, 10.0))

    # 4. Determine JSON report path
    if args.output:
        json_output_path = args.output
    else:
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_output_path = f"scan_report_{timestamp_str}.json"

    # 5. Execute Scan
    scan_start = time.time()
    findings = run_security_audit(
        targets=targets,
        ports=ports,
        concurrency_limit=threads,
        socket_timeout=timeout,
        enable_banners=not args.no_banner,
        verbose=args.verbose,
    )
    scan_duration = time.time() - scan_start

    # 6. Render Terminal Output
    display_console_report(
        target_spec=args.target,
        total_targets=len(targets),
        ports_scanned=len(ports),
        duration=scan_duration,
        findings=findings,
    )

    # 7. Write JSON Report
    saved_file = export_json_report(
        output_path=json_output_path,
        target_spec=args.target,
        total_targets=len(targets),
        ports=ports,
        duration=scan_duration,
        concurrency=threads,
        timeout=timeout,
        findings=findings,
    )

    if saved_file:
        print(f"[*] Programmatic JSON report saved successfully to: {os.path.abspath(saved_file)}")
    print("=" * 78)


if __name__ == "__main__":
    main()
