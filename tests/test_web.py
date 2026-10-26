from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import closing
import json
import sqlite3
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from iriscore.web_audit import audit_web, check_sqli, validate_scope


class LabHandler(BaseHTTPRequestHandler):
    requests_seen = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlsplit(self.path)
        self.requests_seen.append(parts.path)
        if parts.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/must-not-follow')
            self.end_headers()
            return
        value = parse_qs(parts.query).get('id', ['1'])[0]
        status, body = 200, '<html>Lab endpoint</html>'
        if parts.path in ('/unsafe', '/safe'):
            with closing(sqlite3.connect(':memory:')) as con:
                con.execute('CREATE TABLE users(id TEXT)')
                try:
                    if parts.path == '/unsafe':
                        con.execute("SELECT id FROM users WHERE id='" + value + "'")
                    else:
                        con.execute('SELECT id FROM users WHERE id=?', (value,))
                except sqlite3.Error:
                    status, body = 500, 'sqlite3.OperationalError: unrecognized token'
        if parts.path == '/baseline-error':
            body = 'sqlite3.OperationalError: existing issue'
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Set-Cookie', 'session=fixture-cookie-never-report; Path=/')
        self.end_headers()
        self.wfile.write(body.encode())


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), LabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_http_checks_omit_cookie_and_query_values(self):
        report = audit_web(self.origin + '/?token=fixture-private-value', self.origin)
        encoded = json.dumps(report)
        self.assertNotIn('fixture-cookie-never-report', encoded)
        self.assertNotIn('fixture-private-value', encoded)
        self.assertIn('WEB007', [f['rule'] for f in report['findings']])

    def test_real_local_sql_error_probe_and_safe_control(self):
        unsafe = check_sqli(self.origin + '/unsafe?id=1', self.origin, 'id', delay=0)
        self.assertEqual(len(unsafe['data']['requests']), 4)
        self.assertEqual(unsafe['findings'][0]['rule'], 'SQL201')
        self.assertEqual(unsafe['findings'][0]['status'], 'potential')
        safe = check_sqli(self.origin + '/safe?id=1', self.origin, 'id', delay=0)
        self.assertEqual(safe['findings'], [])
        self.assertEqual(safe['status'], 'completed')

    def test_existing_sql_errors_are_not_injection_evidence(self):
        report = check_sqli(self.origin + '/baseline-error?id=1', self.origin, 'id', delay=0)
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['status'], 'inconclusive')
        self.assertEqual(len(report['data']['requests']), 2)

    def test_redirect_not_followed(self):
        report = audit_web(self.origin + '/redirect', self.origin)
        self.assertEqual(report['status'], 'partial')
        self.assertNotIn('/must-not-follow', LabHandler.requests_seen)

    def test_scope_and_ambiguous_parameters_rejected(self):
        with self.assertRaises(ValueError):
            validate_scope('http://example.com/', self.origin)
        with self.assertRaises(ValueError):
            validate_scope('http://user:pass@127.0.0.1/', self.origin)
        with self.assertRaises(ValueError):
            check_sqli(self.origin + '/?id=1&id=2', self.origin, 'id', delay=0)
