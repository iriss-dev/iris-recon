import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import iris_recon
from iriscore.model import assessment, finding
from iriscore.reporting import save_assessment, render_assessment


class ReportingTests(unittest.TestCase):
    def test_html_is_escaped_csv_is_inert_and_manifest_matches(self):
        report = assessment('test', '<script>bad()</script>', findings=[finding(
            'TEST', '=HYPERLINK("bad")', '<img src=x onerror=alert(1)>', 'medium', 'low',
            {'value': '</script><script>bad()</script>'}, 'Review manually.')])
        with tempfile.TemporaryDirectory() as tmp:
            save_assessment(report, tmp)
            path = Path(tmp)
            rendered = (path / 'report.html').read_text(encoding='utf-8')
            self.assertNotIn('<script>bad()', rendered)
            self.assertNotIn('<img src=x', rendered)
            self.assertIn('script-src \'sha256-', rendered)
            self.assertIn("'=HYPERLINK", (path / 'findings.csv').read_text(encoding='utf-8-sig'))
            manifest = json.loads((path / 'manifest.json').read_text())
            for name, digest in manifest['files'].items():
                self.assertEqual(hashlib.sha256((path / name).read_bytes()).hexdigest(), digest)

    def test_stale_comparison_is_cleared(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = assessment('test', 'Test')
            report['comparison'] = {'changes': [], 'warning': 'test'}
            save_assessment(report, tmp)
            del report['comparison']
            save_assessment(report, tmp)
            self.assertIsNone(json.loads((Path(tmp) / 'changes.json').read_text()))

    def test_encoded_xml_entities_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'evil.xml'
            path.write_bytes('<?xml version="1.0" encoding="utf-16"?><!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun>&x;</nmaprun>'.encode('utf-16'))
            with self.assertRaisesRegex(ValueError, 'entity'):
                iris_recon.parse_xml(path)

    def test_cli_priority_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'query.sql'
            path.write_text('DELETE FROM users;', encoding='utf-8')
            self.assertEqual(iris_recon.main(['sql-query', str(path), '--out', str(Path(tmp) / 'out'), '--fail-on', 'high']), 2)
