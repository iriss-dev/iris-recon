"""Unit tests for INMAP advanced features: FastScan, Threat Intel, Subdomains, and MCP Server."""
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import inmap
from inmapcore.fastscan import parse_port_list, run_fast_scan
from inmapcore.intel import classify_ip
from inmapcore.subdomains import query_crt_sh, audit_subdomains
from inmapcore.mcp_server import handle_call_tool, TOOLS_METADATA


class InmapFeatureTests(unittest.TestCase):
    def test_parse_port_list(self):
        self.assertEqual(parse_port_list('22,80,443'), [22, 80, 443])
        self.assertEqual(parse_port_list('80-83'), [80, 81, 82, 83])
        self.assertEqual(parse_port_list('22, 80-82, 443'), [22, 80, 81, 82, 443])
        with self.assertRaises(ValueError):
            parse_port_list('invalid')
        with self.assertRaises(ValueError):
            parse_port_list('80-70')
        with self.assertRaises(ValueError):
            parse_port_list('70000')

    def test_intel_classification(self):
        # Cloudflare IP
        cf = classify_ip('104.16.12.34')
        self.assertEqual(cf['provider'], 'Cloudflare')
        self.assertEqual(cf['category'], 'cdn')
        self.assertIn('cdn-edge-proxy', cf['risk_tags'])

        # AWS IP
        aws = classify_ip('54.239.28.85')
        self.assertEqual(aws['provider'], 'AWS')
        self.assertEqual(aws['category'], 'cloud')
        self.assertIn('direct-cloud-host', aws['risk_tags'])

        # RFC1918 Private
        priv = classify_ip('192.168.1.100')
        self.assertEqual(priv['provider'], 'Private RFC1918 / Local')
        self.assertTrue(priv['is_private'])
        self.assertIn('internal-network', priv['risk_tags'])

        # Loopback
        loop = classify_ip('127.0.0.1')
        self.assertEqual(loop['provider'], 'Localhost')
        self.assertTrue(loop['is_loopback'])

    def test_subdomains_sensitive_patterns(self):
        mock_subs = [
            'example.com',
            'dev.example.com',
            'admin.example.com',
            'vpn.example.com',
            'static.example.com'
        ]
        # Run audit without resolving DNS to verify rule triggers
        report = audit_subdomains('example.com', known_subdomains=mock_subs, resolve_dns=False)
        self.assertEqual(report['kind'], 'subdomains')
        rule_ids = {f['rule'] for f in report['findings']}
        self.assertIn('SUB001', rule_ids)  # dev.example.com
        self.assertIn('SUB002', rule_ids)  # admin.example.com, vpn.example.com

    def test_native_fast_scan_scope_enforcement(self):
        # Must be in authorized scope
        with self.assertRaises(ValueError):
            run_fast_scan('192.168.1.1', '10.0.0.0/8', '80')

    def test_mcp_server_tools_metadata_and_dispatch(self):
        names = {t['name'] for t in TOOLS_METADATA}
        self.assertIn('inmap_fast_scan', names)
        self.assertIn('inmap_subdomain_recon', names)
        self.assertIn('inmap_ip_intel', names)
        self.assertIn('inmap_audit_web', names)
        self.assertIn('inmap_audit_sql', names)
        self.assertIn('inmap_audit_credentials', names)

        # Dispatch IP intel
        res = handle_call_tool('inmap_ip_intel', {'ip': '127.0.0.1'})
        self.assertEqual(res['provider'], 'Localhost')

        with self.assertRaises(ValueError):
            handle_call_tool('unknown_tool', {})

    def test_cli_doctor_and_intel(self):
        # Run CLI doctor
        ret = inmap.main(['doctor'])
        self.assertEqual(ret, 0)

        # Run CLI intel
        ret = inmap.main(['intel', '104.16.0.1'])
        self.assertEqual(ret, 0)

    def test_cli_native_scan_dry_run(self):
        # Run CLI scan in native mode with dry-run
        ret = inmap.main(['scan', '127.0.0.1', '--scope', '127.0.0.1', '--engine', 'native', '--dry-run'])
        self.assertEqual(ret, 0)


if __name__ == '__main__':
    unittest.main()
