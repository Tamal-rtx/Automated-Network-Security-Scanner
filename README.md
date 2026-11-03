# Automated Network Security Scanner & Port Mapper (NetScan Sentinel)

[![Python Standard Library](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Dependencies: Zero](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20StdLib)-brightgreen.svg)](#)
[![Security Auditing](https://img.shields.io/badge/Domain-Defensive%20Security-purple.svg)](#)

A high-performance, native Python network audit utility designed for systems engineers, network administrators, and cybersecurity professionals. It audits target IP addresses, hostnames, and CIDR subnets for exposed TCP endpoints, extracts service identification banners, classifies exposure risk levels, and generates structured reports in both GitHub-flavored Markdown and machine-readable JSON.

---

## Key Technical Features

* **Multi-Threaded Concurrency:** Powered by `concurrent.futures.ThreadPoolExecutor` for asynchronous socket connection mapping, supporting hundreds of concurrent operations without packet starvation or socket exhaustion.
* **Pure Python Socket Engine:** Implemented with native BSD-socket calls (`socket.socket`, `connect_ex`, `setsockopt`). Requires no external CLI utilities such as Nmap or Masscan.
* **In-Stream Banner Grabbing:** Non-destructive two-phase banner inspection:
  1. *Passive phase:* Captures unsolicited service greetings (e.g., SSH, FTP, SMTP).
  2. *Active phase:* Issues safe protocol probes (e.g., HTTP `HEAD`, TLS SNI handshake).
* **Security Risk Scoring:** Evaluates open ports against a built-in network hygiene knowledge base, categorizing findings into **High**, **Medium**, **Low**, and **Info** risk levels with actionable mitigation guidelines.
* **Dual Reporting Output:** Auto-generates a formatted Markdown/ASCII summary table on standard output and saves a timestamped, schema-validated JSON report for SIEM ingestion or CI/CD pipelines.
* **Zero Third-Party Dependencies:** Relies entirely on the Python Standard Library (`socket`, `concurrent.futures`, `ipaddress`, `argparse`, `json`, `ssl`).

---

## Architecture & Engineering Design

```
+-----------------------------------------------------------------------------------+
|                                 CLI Entrypoint                                    |
|                       (argparse: targets, ports, threads, timeout)                |
+-----------------------------------------------------------------------------------+
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
         Target Resolver (ipaddress)               Port Parser (Range & Lists)
         - Single Host (IPv4 / IPv6)               - Curated Default Ports
         - CIDR Subnets (e.g. /28, /24)            - Custom Range (e.g. 1-1024)
         - DNS Hostname Resolution                 - Specific Ports (e.g. 80,443)
                    └────────────────────┬────────────────────┘
                                         ▼
                          ThreadPoolExecutor Task Pool
                          (Worker Threads: 10 - 200)
                                         │
                     ┌───────────────────┴───────────────────┐
                     ▼                                       ▼
        Socket Connect (`connect_ex`)             In-Stream Banner Grabber
        - Granular Socket Timeout                 - Passive Greeting Read
        - Connection Latency (ms)                 - Active HTTP / TLS Probes
                     └───────────────────┬───────────────────┘
                                         ▼
                            Security Knowledge Base
                            - Risk Classification (High/Med/Low)
                            - Actionable Recommendations
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
        Standard Output Report                    JSON Artifact Report
        (Formatted Markdown Table)               (Full Telemetry & Summary)
```

### 1. Thread Synchronization & Concurrency Safety
The scanner separates task generation, worker execution, and reporting synchronization:
* **Worker Pool:** `concurrent.futures.ThreadPoolExecutor` controls the maximum active thread pool, preventing thread flooding and OS file descriptor limits.
* **Thread-Safe Metrics:** A dedicated `ScanMetrics` monitor uses a `threading.Lock()` primitive to synchronize completed probe counts and real-time status updates without race conditions.
* **Console Synchronization:** Standard output operations from concurrent workers are serialized via a shared output lock (`print_lock`), eliminating terminal text interleaving.
* **Graceful Interrupt Handling:** Captures `KeyboardInterrupt` (Ctrl+C), invokes `executor.shutdown(wait=False, cancel_futures=True)`, and flushes any partial results to the final report without hanging.

### 2. Socket Timeout & Reliability Strategy
* **Explicit Non-Blocking Checks:** Uses `sock.connect_ex((ip, port))`, which directly surfaces OS connection return codes (0 for success, `ECONNREFUSED`, `ETIMEDOUT`, etc.) rather than throwing blocking exceptions.
* **Adaptive Banner Timeouts:** Passive greeting detection is bounded by `min(timeout, 0.7)` seconds to avoid unnecessary idling on silent services.
* **Socket Cleanup:** Every socket instance is bound to a `try...finally` block to ensure immediate socket closure, reclaiming local ports and preventing socket exhaustion (`TIME_WAIT` accumulation).

---

## Installation & Requirements

* **Python 3.8+** (Works across Linux, macOS, and Windows)
* **Dependencies:** None (Pure Standard Library).

Clone or copy `scanner.py` into your working directory:
```bash
git clone https://github.com/your-org/netscan-sentinel.git
cd netscan-sentinel
```

Verify your Python environment:
```bash
python --version
```

---

## Command Line Usage

```
usage: scanner.py [-h] -t TARGET [-p PORTS] [-w THREADS] [--timeout TIMEOUT]
                  [-o OUTPUT] [--no-banner] [-v]
```

### Arguments & Options

| Flag | Name | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-t` | `--target` | `str` | *Required* | Target IP, CIDR subnet (e.g., `192.168.1.0/28`), or hostname (`example.com`). |
| `-p` | `--ports` | `str` | `default` | Ports to scan: `default` (mapped risk ports), `all` (1-65535), or list/ranges (`80,443`, `1-1024`). |
| `-w` | `--threads` | `int` | `50` | Maximum number of concurrent worker threads. |
| | `--timeout` | `float` | `1.5` | Socket connection timeout in seconds. |
| `-o` | `--output` | `str` | `None` | Custom output filepath for JSON report (defaults to `scan_report_<timestamp>.json`). |
| | `--no-banner` | `flag` | `False` | Skips banner extraction for accelerated discovery scans. |
| `-v` | `--verbose` | `flag` | `False` | Prints closed and filtered endpoints during execution. |

---

## Operational Examples

### 1. Audit Local Host Using Default Port Profile
```bash
python scanner.py --target 127.0.0.1
```

### 2. Scan Specific Critical Infrastructure Ports with 100 Worker Threads
```bash
python scanner.py --target 192.168.1.15 --ports 21,22,23,80,443,445,3389,8080 --threads 100
```

### 3. Scan a Small Subnet (/28) for Exposed Database Endpoints
```bash
python scanner.py --target 10.0.0.0/28 --ports 1433,1521,3306,5432,6379,27017 --timeout 1.0
```

### 4. Comprehensive Range Scan with Custom JSON Output
```bash
python scanner.py --target scanme.nmap.org --ports 1-1000 --threads 80 --output audit_report.json
```

---

## Sample Reports

### Terminal Summary & Markdown Table
```
================================================================================
                     NETWORK SECURITY AUDIT SUMMARY REPORT
================================================================================
 Execution Timestamp:  2026-11-03 01:10:00
 Target Specification: 192.168.1.20 (1 host(s))
 Ports Scanned/Host:   27
 Total Scan Duration:  1.42 seconds
 Total Endpoints Open: 3
--------------------------------------------------------------------------------
 RISK EXPOSURE PROFILE:
   - HIGH Risk:   1   (Action Required: Insecure or high-risk administrative services detected)
   - MEDIUM Risk: 1   (Review cleartext protocols and TLS configurations)
   - LOW Risk:    1   
   - INFO:        0   
================================================================================

### DETAILED FINDINGS TABLE

| Target IP    | Port  | Service  | Risk Level | Banner / Info                                 | Recommendation                                                |
| 192.168.1.20 | 22    | SSH      | Low        | SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6       | Ensure root login is disabled and enforce key authentication. |
| 192.168.1.20 | 80    | HTTP     | Medium     | HTTP/1.1 200 OK / Server: nginx/1.18.0        | Implement 301 redirect to HTTPS and enforce HSTS headers.     |
| 192.168.1.20 | 3389  | RDP      | High       | Service active (no banner advertised)         | Enforce Network Level Auth (NLA), place behind VPN with MFA.  |
```

### Machine-Readable JSON Schema (`scan_report.json`)
```json
{
  "metadata": {
    "scanner": "NetScan Sentinel - Automated Network Security Scanner",
    "version": "1.0.0",
    "generated_utc": "2026-11-02T19:40:00.123456+00:00",
    "target_input": "192.168.1.20",
    "resolved_targets_count": 1,
    "ports_scanned_count": 27,
    "concurrency_limit": 50,
    "socket_timeout_seconds": 1.5,
    "scan_duration_seconds": 1.42
  },
  "summary": {
    "total_open_ports": 3,
    "risk_distribution": {
      "high": 1,
      "medium": 1,
      "low": 1,
      "info": 0
    }
  },
  "findings": [
    {
      "target_host": "192.168.1.20",
      "ip_address": "192.168.1.20",
      "port": 22,
      "service": "SSH",
      "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
      "risk_level": "Low",
      "risk_summary": "Encrypted remote administration service.",
      "recommendation": "Ensure root login is disabled and enforce public-key authentication.",
      "latency_ms": 1.82
    }
  ]
}
```

---

## Security & Operational Safeguards

1. **Self-DoS Mitigation:** The thread pool limit is bounded to prevent thread starvation or socket exhaustion on the local operating system.
2. **Subnet Scope Boundary:** CIDR parsing enforces a safe maximum ceiling of 1,024 hosts (`/22`) per run to avoid unintentional broad-scale broadcast sweeps.
3. **Safe String Sanitization:** Banners are sanitized to eliminate escape sequences, terminal control codes, and non-printable binary bytes before terminal printing or JSON serializing.
4. **Authorized Auditing Only:** This tool is designed strictly for authorized defensive auditing, infrastructure inventory mapping, and internal verification. Ensure explicit authorization prior to testing network assets.

