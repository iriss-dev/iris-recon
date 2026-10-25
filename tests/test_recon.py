import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import iris_recon as recon


XML = '''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" args="nmap example" startstr="Synthetic fixture">
<scaninfo type="connect" protocol="tcp" services="22,443"/>
<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><extraports state="closed" count="1"/><port portid="22" protocol="tcp"><state state="open"/>
<service name="ssh" product="&lt;script&gt;alert(1)&lt;/script&gt;" version="1" method="probed" conf="10"><cpe>cpe:/a:example:ssh:1</cpe></service>
<script id="example" output="evidence"/></port></ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>'''


class ReconTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.xml = Path(self.temp.name) / 'scan.xml'
        self.xml.write_text(XML, encoding='utf-8')

    def test_parse_evidence_and_html_escaping(self):
        report = recon.parse_xml(self.xml)
        port = report['hosts'][0]['ports'][0]
        self.assertEqual(port['state'], 'open')
        self.assertEqual(port['cpe'], ['cpe:/a:example:ssh:1'])
        self.assertEqual(port['scripts'][0]['output'], 'evidence')
        rendered = recon.render_html(report)
        self.assertNotIn('<script>alert', rendered)
        self.assertIn('&lt;script&gt;alert', rendered)
        self.assertIn('completed', rendered)

    def test_changes_do_not_claim_closure(self):
        old = recon.parse_xml(self.xml)
        self.xml.write_text(XML.replace('portid="22"', 'portid="443"'), encoding='utf-8')
        delta = recon.compare(old, recon.parse_xml(self.xml))
        self.assertEqual([x['change'] for x in delta['changes']],
                         ['no_longer_observed', 'newly_observed'])
        self.assertIn('not proof of closure', delta['warning'])

    def test_service_change_and_coverage(self):
        old = recon.parse_xml(self.xml)
        self.xml.write_text(XML.replace('version="1"', 'version="2"').replace('22,443', '22'), encoding='utf-8')
        delta = recon.compare(old, recon.parse_xml(self.xml))
        self.assertEqual(delta['changes'][0]['change'], 'changed')
        self.assertTrue(delta['coverage_changed'])

    def test_incomplete_and_entity_input(self):
        self.xml.write_text(XML.replace('exit="success"', 'exit="error"'), encoding='utf-8')
        self.assertIn('incomplete / unknown', recon.render_html(recon.parse_xml(self.xml)))
        self.xml.write_text('<!DOCTYPE nmaprun [<!ENTITY a "x">]><nmaprun/>', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'entity'):
            recon.parse_xml(self.xml)

    def test_invalid_input_is_reported_by_cli(self):
        for xml in ('<nmaprun>', '<unrelated/>'):
            with self.subTest(xml=xml):
                self.xml.write_text(xml, encoding='utf-8')
                self.assertEqual(recon.main(['report', str(self.xml)]), 1)

    def test_scope_and_injection_validation(self):
        args = argparse.Namespace(target='127.0.0.1', scope='127.0.0.0/8', ports='22,80-90',
                                  max_rate=100, skip_discovery=False)
        cmd = recon.scan_command(args, 'nmap', 'scan.xml')
        self.assertIn('-sT', cmd)
        self.assertEqual(cmd[-1], '127.0.0.1')
        args.target = '192.0.2.1'
        with self.assertRaisesRegex(ValueError, 'scope'):
            recon.scan_command(args, 'nmap', 'scan.xml')
        for ports in ('22;whoami', '0', '65536', '80-22', '-sC'):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                recon.validate_ports(ports)
        args.target, args.scope = '::1', '::1/128'
        self.assertIn('-6', recon.scan_command(args, 'nmap', 'scan.xml'))

    def test_offline_cli_and_baseline(self):
        out = Path(self.temp.name) / 'report'
        self.assertEqual(recon.main(['report', str(self.xml), '--out', str(out),
                                     '--baseline', str(self.xml)]), 0)
        for filename in ('report.html', 'report.json', 'changes.json'):
            self.assertTrue((out / filename).exists())

    def test_scan_orchestration_without_network(self):
        out = Path(self.temp.name) / 'live'

        def fake_nmap(cmd, **kwargs):
            self.assertFalse(kwargs['shell'])
            Path(cmd[cmd.index('-oX') + 1]).write_text(XML, encoding='utf-8')
            return argparse.Namespace(returncode=0, stdout='fixture', stderr='')

        with patch('iris_recon.shutil.which', return_value='nmap'), patch(
                'iris_recon.subprocess.run', side_effect=fake_nmap):
            argv = ['scan', '127.0.0.1', '--scope', '127.0.0.1', '--out', str(out)]
            self.assertEqual(recon.main(argv), 0)
            self.assertTrue((out / 'command.json').exists())
            self.assertEqual(recon.main(argv), 1)  # Preserve prior evidence.


if __name__ == '__main__':
    unittest.main()
