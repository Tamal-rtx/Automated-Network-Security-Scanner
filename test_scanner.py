#!/usr/bin/env python3
"""
Unit and Integration Test Suite for NetScan Sentinel
=====================================================
Validates parsing logic, risk categorization, banner sanitization,
JSON serialization, and error boundaries using standard unittest.
"""

import json
import os
import tempfile
import unittest

from scanner import (
    PORT_KNOWLEDGE_BASE,
    PortFinding,
    export_json_report,
    format_markdown_table,
    parse_port_selection,
    resolve_target,
    sanitize_banner_text,
)


class TestTargetResolution(unittest.TestCase):
    """Tests target parsing and validation."""

    def test_single_ipv4(self):
        targets = resolve_target("192.168.1.1")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0], ("192.168.1.1", "192.168.1.1"))

    def test_cidr_range(self):
        targets = resolve_target("10.0.0.0/30")
        # /30 has 2 usable host addresses (10.0.0.1, 10.0.0.2)
        self.assertEqual(len(targets), 2)
        ips = [t[1] for t in targets]
        self.assertIn("10.0.0.1", ips)
        self.assertIn("10.0.0.2", ips)

    def test_localhost_hostname(self):
        targets = resolve_target("localhost")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0][1], "127.0.0.1")

    def test_invalid_target_empty(self):
        with self.assertRaises(ValueError):
            resolve_target("   ")

    def test_invalid_target_bad_cidr(self):
        with self.assertRaises(ValueError):
            resolve_target("999.999.999.999/24")


class TestPortParsing(unittest.TestCase):
    """Tests port selection grammar and boundary limits."""

    def test_default_ports(self):
        ports = parse_port_selection(None)
        self.assertTrue(len(ports) > 20)
        self.assertIn(80, ports)
        self.assertIn(443, ports)

    def test_comma_separated_ports(self):
        ports = parse_port_selection("22,80,443")
        self.assertEqual(ports, [22, 80, 443])

    def test_range_ports(self):
        ports = parse_port_selection("80-84")
        self.assertEqual(ports, [80, 81, 82, 83, 84])

    def test_combined_syntax(self):
        ports = parse_port_selection("21, 80-82, 443")
        self.assertEqual(ports, [21, 80, 81, 82, 443])

    def test_out_of_bounds_ports(self):
        with self.assertRaises(ValueError):
            parse_port_selection("0")
        with self.assertRaises(ValueError):
            parse_port_selection("65536")


class TestBannerSanitization(unittest.TestCase):
    """Tests banner string cleanup and protection against control chars."""

    def test_clean_ascii(self):
        raw = b"SSH-2.0-OpenSSH_8.9p1\r\n"
        cleaned = sanitize_banner_text(raw)
        self.assertEqual(cleaned, "SSH-2.0-OpenSSH_8.9p1")

    def test_http_header_extraction(self):
        raw = b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026\r\nServer: nginx/1.24.0\r\n\r\n"
        cleaned = sanitize_banner_text(raw)
        self.assertIn("HTTP/1.1 200 OK", cleaned)
        self.assertIn("Server: nginx/1.24.0", cleaned)

    def test_binary_garbage_handling(self):
        raw = b"\x00\x01\x02\x03\xff\xfe"
        cleaned = sanitize_banner_text(raw)
        self.assertEqual(cleaned, "Binary response (unprintable)")


class TestRiskClassification(unittest.TestCase):
    """Validates security risk mapping for critical ports."""

    def test_telnet_high_risk(self):
        _, risk, _, _ = PORT_KNOWLEDGE_BASE[23]
        self.assertEqual(risk, "High")

    def test_smb_high_risk(self):
        _, risk, _, _ = PORT_KNOWLEDGE_BASE[445]
        self.assertEqual(risk, "High")

    def test_ssh_low_risk(self):
        _, risk, _, _ = PORT_KNOWLEDGE_BASE[22]
        self.assertEqual(risk, "Low")

    def test_http_medium_risk(self):
        _, risk, _, _ = PORT_KNOWLEDGE_BASE[80]
        self.assertEqual(risk, "Medium")


class TestReportGeneration(unittest.TestCase):
    """Tests Markdown and JSON report outputs."""

    def setUp(self):
        self.dummy_findings = [
            PortFinding(
                target_host="192.168.1.10",
                ip_address="192.168.1.10",
                port=22,
                service="SSH",
                banner="SSH-2.0-OpenSSH_8.2p1",
                risk_level="Low",
                risk_summary="Encrypted remote administration",
                recommendation="Use keys",
                latency_ms=1.25,
            ),
            PortFinding(
                target_host="192.168.1.10",
                port=23,
                ip_address="192.168.1.10",
                service="Telnet",
                banner="Telnet banner",
                risk_level="High",
                risk_summary="Cleartext console",
                recommendation="Decommission",
                latency_ms=2.10,
            ),
        ]

    def test_markdown_formatting(self):
        table = format_markdown_table(self.dummy_findings)
        self.assertIn("| Target IP", table)
        self.assertIn("192.168.1.10", table)
        self.assertIn("SSH", table)
        self.assertIn("Telnet", table)

    def test_json_export(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            saved = export_json_report(
                output_path=temp_path,
                target_spec="192.168.1.10",
                total_targets=1,
                ports=[22, 23],
                duration=1.2,
                concurrency=5,
                timeout=1.0,
                findings=self.dummy_findings,
            )
            self.assertTrue(os.path.exists(saved))
            with open(saved, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["summary"]["total_open_ports"], 2)
            self.assertEqual(data["summary"]["risk_distribution"]["high"], 1)
            self.assertEqual(data["summary"]["risk_distribution"]["low"], 1)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()

