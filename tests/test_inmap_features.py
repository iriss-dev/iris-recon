from pathlib import Path
import tempfile
import unittest

import inmap
from inmapcore.credentials import extract, shannon_entropy
from inmapcore.deps_audit import audit_dependencies
from inmapcore.dns_audit import audit_dns
from inmapcore.fastscan import parse_port_list, run_fast_scan
from inmapcore.iac_audit import audit_iac, check_dockerfile, check_workflow
from inmapcore.intel import classify_ip
from inmapcore.mcp_server import TOOLS_METADATA, handle_call_tool
from inmapcore.model import finding
from inmapcore.subdomains import audit_subdomains


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
        cf = classify_ip('104.16.12.34')
        self.assertEqual(cf['provider'], 'Cloudflare')
        self.assertEqual(cf['category'], 'cdn')
        self.assertIn('cdn-edge-proxy', cf['risk_tags'])

        aws = classify_ip('54.239.28.85')
        self.assertEqual(aws['provider'], 'AWS')
        self.assertEqual(aws['category'], 'cloud')

        priv = classify_ip('192.168.1.100')
        self.assertTrue(priv['is_private'])
        self.assertIn('internal-network', priv['risk_tags'])

        loop = classify_ip('127.0.0.1')
        self.assertTrue(loop['is_loopback'])

    def test_subdomains_sensitive_patterns(self):
        subs = ['example.com', 'dev.example.com', 'admin.example.com', 'vpn.example.com']
        report = audit_subdomains('example.com', known_subdomains=subs, resolve_dns=False)
        rules = {f['rule'] for f in report['findings']}
        self.assertIn('SUB001', rules)
        self.assertIn('SUB002', rules)

    def test_dns_spf_and_dmarc_checks(self):
        weak = audit_dns('example.com', txt_records=['v=spf1 +all'], dmarc_records=['v=DMARC1; p=none;'])
        rules = {f['rule'] for f in weak['findings']}
        self.assertEqual(rules, {'DNS001', 'DNS002'})

        strong = audit_dns('example.com', txt_records=['v=spf1 include:_spf.google.com -all'], dmarc_records=['v=DMARC1; p=reject;'])
        self.assertEqual(strong['findings'], [])

    def test_token_signatures_and_entropy(self):
        sample = 'const key = "AKIAIOSFODNN7EXAMPLE";\n'
        found = extract(sample, '.js')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['key'], 'signature:aws_access_key')
        self.assertGreater(shannon_entropy('AKIAIOSFODNN7EXAMPLE'), 3.0)

    def test_iac_dockerfile_workflow_and_crypto(self):
        df_findings = check_dockerfile('FROM ubuntu:latest\nENV API_SECRET=123\nRUN echo hi\n', 'Dockerfile')
        self.assertEqual({f['rule'] for f in df_findings}, {'IAC001', 'IAC002', 'IAC004'})

        wf_findings = check_workflow('on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo "${{ github.event.issue.title }}"\n', 'ci.yml')
        self.assertEqual({f['rule'] for f in wf_findings}, {'CI001', 'CI002', 'CI003'})

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'app.py'
            p.write_text('import hashlib, requests\nhashlib.md5(b"x")\nrequests.get("https://example.com", verify=False)\n', encoding='utf-8')
            rep = audit_iac(p)
            self.assertEqual({f['rule'] for f in rep['findings']}, {'CRYP001', 'CRYP003'})

    def test_dependencies_and_sbom(self):
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / 'requirements.txt'
            req.write_text('flask==3.0.0\nrequests>=2.31.0\n', encoding='utf-8')
            rep = audit_dependencies(req, check_osv=False)
            self.assertEqual(len(rep['data']['dependencies']), 2)
            self.assertEqual(rep['data']['sbom']['bomFormat'], 'CycloneDX')
            self.assertEqual([f['rule'] for f in rep['findings']], ['DEP002'])

    def test_standards_attached_to_findings(self):
        item = finding('SQL101', 'Dynamic SQL', 'app.py:10', 'medium', 'high', {}, 'Fix it')
        self.assertEqual(item.get('cwe'), 'CWE-89')
        self.assertEqual(item.get('owasp'), 'OWASP A03:2021')

    def test_native_fast_scan_scope_enforcement(self):
        with self.assertRaises(ValueError):
            run_fast_scan('192.168.1.1', '10.0.0.0/8', '80')

    def test_mcp_server_dispatch(self):
        names = {t['name'] for t in TOOLS_METADATA}
        self.assertIn('inmap_audit_dns', names)
        self.assertIn('inmap_audit_iac', names)
        self.assertIn('inmap_audit_deps', names)
        res = handle_call_tool('inmap_ip_intel', {'ip': '127.0.0.1'})
        self.assertEqual(res['provider'], 'Localhost')

    def test_cli_commands(self):
        self.assertEqual(inmap.main(['doctor']), 0)
        self.assertEqual(inmap.main(['intel', '104.16.0.1']), 0)
        self.assertEqual(inmap.main(['scan', '127.0.0.1', '--scope', '127.0.0.1', '--engine', 'native', '--dry-run']), 0)


if __name__ == '__main__':
    unittest.main()
