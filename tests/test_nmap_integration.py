"""Real Nmap against an ephemeral localhost HTTP server; no external targets."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

import iris_recon


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><title>Iris test</title>Local integration test</html>')


@unittest.skipUnless(shutil.which('nmap'), 'Nmap is not installed')
class NmapIntegrationTest(unittest.TestCase):
    def test_real_localhost_scan(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'scan'
                result = iris_recon.main(['scan', '127.0.0.1', '--scope', '127.0.0.1/32',
                    '--ports', str(server.server_port), '--skip-discovery', '--out', str(out)])
                self.assertEqual(result, 0)
                report = iris_recon.parse_xml(out / 'scan.xml')
                observed = report['hosts'][0]['ports'][0]
                self.assertEqual((observed['port'], observed['state']), (server.server_port, 'open'))
                self.assertTrue((out / 'report.html').exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
