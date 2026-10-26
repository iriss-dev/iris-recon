"""Network, web and SQL assessment tools. Python 3.11+."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sqlite3
import http.client
import ssl
import xml.etree.ElementTree as ET

from iriscore import __version__
from iriscore.nmapio import parse_xml, compare, render_html, save_report
from iriscore.model import assessment, read_limited, PRIORITIES
from iriscore.reporting import save_assessment
from iriscore.sql_audit import audit_source, audit_query, audit_sqlite
from iriscore.web_audit import audit_web, check_sqli
from iriscore.credentials import audit_credentials


def validate_ports(text):
    if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', text):
        raise ValueError('Ports must be numeric, e.g. 22,80,443 or 1-1024')
    for part in text.split(','):
        pair = [int(x) for x in part.split('-')]
        if not all(1 <= x <= 65535 for x in pair) or pair[0] > pair[-1]:
            raise ValueError('Ports must be ascending and within 1..65535')
    return text


def scan_command(args, executable, destination):
    target = ipaddress.ip_network(args.target, strict=False)
    scope = ipaddress.ip_network(args.scope, strict=False)
    if target.version != scope.version or not target.subnet_of(scope):
        raise ValueError('Target must be inside the declared authorized scope')
    if target.num_addresses > 4096:
        raise ValueError('Split the assessment into scopes of at most 4096 addresses')
    cmd = [executable, '-sT', '-sV', '--version-light', '-T3', '-n',
           '--max-rate', str(args.max_rate), '--host-timeout', '120s',
           '-p', validate_ports(args.ports), '-oX', str(destination)]
    if target.version == 6:
        cmd.append('-6')
    if args.skip_discovery:
        cmd.append('-Pn')
    cmd.append(str(target.network_address) if target.num_addresses == 1 else str(target))
    return cmd


def bounded_rate(value):
    result = int(value)
    if not 1 <= result <= 1000:
        raise argparse.ArgumentTypeError('Rate must be within 1..1000')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=f'Iris Recon {__version__}')
    sub = parser.add_subparsers(dest='action', required=True)
    offline = sub.add_parser('report', help='Analyze existing Nmap XML offline')
    offline.add_argument('xml')
    offline.add_argument('--baseline', help='Previous Nmap XML to compare')
    scan = sub.add_parser('scan', help='Run Nmap on a declared authorized IP scope')
    scan.add_argument('target', help='IPv4/IPv6 address or CIDR; DNS names are not accepted')
    scan.add_argument('--scope', required=True, help='Authorized IP address or CIDR')
    scan.add_argument('--ports', help='Explicit ports override the selected profile')
    scan.add_argument('--profile', choices=['common', 'web', 'database', 'full'], default='common')
    scan.add_argument('--max-rate', type=bounded_rate, default=100)
    scan.add_argument('--skip-discovery', action='store_true', help='Use -Pn if discovery is blocked')
    scan.add_argument('--nmap-path', help='Explicit Nmap executable path')
    scan.add_argument('--dry-run', action='store_true', help='Print the validated command without running it')
    scan.add_argument('--baseline')
    code = sub.add_parser('sql-code', help='Review Python, JavaScript/TypeScript and SQL source')
    code.add_argument('path')
    query = sub.add_parser('sql-query', help='Lint a SQL file without executing it')
    query.add_argument('path')
    database = sub.add_parser('sql-db', help='Inspect a SQLite database in read-only mode')
    database.add_argument('path')
    database.add_argument('--query-file', help='Optional SELECT file for EXPLAIN QUERY PLAN only')
    web = sub.add_parser('web', help='Check HTTP headers, cookie flags and negotiated TLS')
    web.add_argument('url')
    web.add_argument('--scope', required=True, help='Exact authorized URL origin')
    sqli = sub.add_parser('sqli-check', help='Check one GET parameter for repeated SQL-error feedback')
    sqli.add_argument('url')
    sqli.add_argument('--scope', required=True, help='Exact authorized URL origin')
    sqli.add_argument('--param', required=True, help='Existing query parameter to test')
    credentials = sub.add_parser('credentials', help='Find local credential literals and compare rotations')
    credentials.add_argument('path')
    credentials.add_argument('--key-file', default='work/.iris-credential-key', help='Private 32-byte comparison key; created if absent')
    credentials.add_argument('--baseline', help='Previous credentials report.json using the same key')
    credentials.add_argument('--reveal-secrets', action='store_true', help='Include full literal secrets in local reports; keep the outputs private')
    combine = sub.add_parser('combine', help='Combine module report.json files into one assessment')
    combine.add_argument('reports', nargs='+')
    sub.add_parser('doctor', help='Show runtime and Nmap availability; no network scan')
    for command in (offline, scan, code, query, database, web, sqli, credentials, combine):
        command.add_argument('--out', default=f'reports/{command.prog.split()[-1]}', help='Output directory (scan requires a new directory)')
        command.add_argument('--fail-on', choices=['high', 'medium', 'low'], help='Exit 2 if a finding meets this review-priority threshold')
    args = parser.parse_args(argv)
    try:
        if args.action == 'doctor':
            print(json.dumps({'iris_recon': __version__, 'python': sys.version.split()[0],
                              'sqlite': sqlite3.sqlite_version, 'nmap': shutil.which('nmap'),
                              'offline_modules': ['report', 'sql-code', 'sql-query', 'sql-db', 'credentials', 'combine']}, indent=2))
            return 0
        if args.action == 'report':
            report = save_report(args.xml, args.out, args.baseline)
        elif args.action == 'scan':
            executable = str(Path(args.nmap_path).resolve(strict=True)) if args.nmap_path else shutil.which('nmap')
            if not executable:
                raise ValueError('Nmap is not installed or is missing from PATH. Offline report mode remains available.')
            profiles = {'common': '22,80,443,445,3389,8080,8443', 'web': '80,443,8000,8080,8443,8888',
                        'database': '1433,1521,3306,5432,6379,9200,27017', 'full': '1-65535'}
            args.ports = args.ports or profiles[args.profile]
            if args.baseline:
                parse_xml(args.baseline)
            folder = Path(args.out).resolve()
            xml = folder / 'scan.xml'
            cmd = scan_command(args, executable, xml)
            if args.dry_run:
                print(subprocess.list2cmdline(cmd))
                return 0
            folder.mkdir(parents=True, exist_ok=False)
            (folder / 'command.json').write_text(json.dumps(cmd, indent=2), encoding='utf-8')
            print('Running:', subprocess.list2cmdline(cmd))
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, shell=False)
            except subprocess.TimeoutExpired as exc:
                def decode(value):
                    return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
                (folder / 'nmap.log').write_text(decode(exc.stdout) + '\n' + decode(exc.stderr) + '\nProcess exceeded 1800 seconds.', encoding='utf-8')
                raise ValueError(f'Nmap timed out; partial evidence retained in {folder}') from exc
            (folder / 'nmap.log').write_text(result.stdout + '\n' + result.stderr, encoding='utf-8')
            if result.returncode:
                raise ValueError(f'Nmap exited with {result.returncode}; inspect {folder / "nmap.log"}')
            report = save_report(xml, folder, args.baseline)
        else:
            if args.action == 'sql-code':
                report = audit_source(args.path)
            elif args.action == 'sql-query':
                report = audit_query(args.path)
            elif args.action == 'sql-db':
                report = audit_sqlite(args.path, args.query_file)
            elif args.action == 'web':
                report = audit_web(args.url, args.scope)
            elif args.action == 'sqli-check':
                report = check_sqli(args.url, args.scope, args.param)
            elif args.action == 'credentials':
                report = audit_credentials(args.path, args.key_file, args.baseline, args.reveal_secrets)
            else:
                report = assessment('combined', 'Combined assessment', limitations=[
                    'Coverage and limitations belong to the individual module runs below. Review findings are not confirmed vulnerabilities.',
                    'Input reports may contain sensitive evidence, including explicitly revealed credentials. Keep this combined report private.'])
                modules, seen = [], set()
                for path in args.reports:
                    module = json.loads(read_limited(path, 32 * 1024 * 1024))
                    if module.get('schema_version') != 2 or 'findings' not in module or 'kind' not in module:
                        raise ValueError('Combine expects Iris Recon v2 report.json files')
                    for item in module['findings']:
                        if item['id'] not in seen:
                            report['findings'].append(item)
                            seen.add(item['id'])
                    modules.append(module)
                    if module['status'] != 'completed':
                        report['status'] = 'partial'
                report['data']['modules'] = modules
            save_assessment(report, args.out)
        print(f'Report saved to {Path(args.out).resolve() / "report.html"}')
        print(f'{len(report["findings"])} review findings; status: {report["status"]}')
        if args.fail_on and any(PRIORITIES[f['severity']] <= PRIORITIES[args.fail_on] for f in report['findings']):
            return 2
        if report['status'] != 'completed':
            return 3
        return 0
    except (ValueError, OSError, ET.ParseError, subprocess.SubprocessError, sqlite3.Error, http.client.HTTPException, ssl.SSLError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
