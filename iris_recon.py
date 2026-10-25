"""Nmap inventory, offline reporting, and evidence comparison. Python 3.11+."""
import argparse
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


def parse_xml(path):
    raw = Path(path).read_bytes()
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError('XML exceeds the 32 MiB limit')
    if re.search(br'<!\s*ENTITY', raw, re.I):
        raise ValueError('XML entity declarations are unsupported')
    root = ET.fromstring(raw)
    if root.tag != 'nmaprun':
        raise ValueError('Expected an Nmap XML file')
    finished = root.find('runstats/finished')
    hosts = []
    for host in root.findall('host'):
        addresses = [a.get('addr') for a in host.findall('address')
                     if a.get('addrtype') in ('ipv4', 'ipv6')]
        if not addresses:
            continue
        ports = []
        for port in host.findall('ports/port'):
            state = port.find('state')
            svc = port.find('service')
            ports.append({
                'port': int(port.get('portid')), 'protocol': port.get('protocol'),
                'state': state.get('state', 'unknown') if state is not None else 'unknown',
                'reason': state.get('reason', '') if state is not None else '',
                'service': dict(svc.attrib) if svc is not None else {},
                'cpe': [x.text for x in svc.findall('cpe')] if svc is not None else [],
                'scripts': [dict(x.attrib) for x in port.findall('script')],
            })
        status = host.find('status')
        hosts.append({'address': addresses[0], 'addresses': addresses,
                      'state': status.get('state', 'unknown') if status is not None else 'unknown',
                      'hostnames': [x.get('name', '') for x in host.findall('hostnames/hostname')],
                      'ports': sorted(ports, key=lambda p: (p['protocol'], p['port'])),
                      'extraports': [dict(x.attrib) for x in host.findall('ports/extraports')]})
    return {'schema_version': 1, 'source_sha256': hashlib.sha256(raw).hexdigest(),
            'nmap_version': root.get('version', ''), 'arguments': root.get('args', ''),
            'started': root.get('startstr', root.get('start', '')),
            'scaninfo': [dict(x.attrib) for x in root.findall('scaninfo')],
            'finished': dict(finished.attrib) if finished is not None else {},
            'hosts': sorted(hosts, key=lambda h: h['address'])}


def compare(before, after):
    def index(report):
        return {(h['address'], p['protocol'], p['port']): p
                for h in report['hosts'] for p in h['ports']}
    old, new = index(before), index(after)
    changes = []
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        if a is None:
            kind = 'newly_observed'
        elif b is None:
            kind = 'no_longer_observed'
        elif any(a.get(k) != b.get(k) for k in ('state', 'service', 'cpe')):
            kind = 'changed'
        else:
            continue
        changes.append({'address': key[0], 'protocol': key[1], 'port': key[2],
                        'change': kind, 'before': a, 'after': b})
    return {'schema_version': 1,
            'warning': 'Absence is not proof of closure. Compare matching targets, ports and scan settings; discovery and filtering can change visibility.',
            'coverage_changed': before['scaninfo'] != after['scaninfo'],
            'arguments_changed': before['arguments'] != after['arguments'],
            'changes': changes}


def render_html(report, delta=None):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    open_count = 0
    for host in report['hosts']:
        for port in host['ports']:
            svc = port['service']
            open_count += port['state'] == 'open'
            evidence = ' '.join(svc.get(k, '') for k in ('name', 'product', 'version', 'extrainfo')).strip()
            rows.append('<tr>' + ''.join('<td>' + esc(v) + '</td>' for v in
                        (host['address'], f"{port['port']}/{port['protocol']}",
                         port['state'], evidence or 'Unknown', svc.get('method', 'unknown'),
                         svc.get('conf', 'unknown'))) + '</tr>')
    changes = ''
    if delta is not None:
        changes = '<h2>Changes</h2><p>' + esc(delta['warning']) + '</p><pre>' + esc(json.dumps(delta, indent=2)) + '</pre>'
    complete = report['finished'].get('exit') == 'success'
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Iris Recon · Assessment report</title>
<style>body{margin:0;background:#101521;color:#e3e8f1;font:16px system-ui;line-height:1.6}main{max-width:1200px;margin:auto;padding:40px 24px}h1{color:#7ce2ca;font-size:38px}h2{margin-top:36px}.summary{border:1px solid #344457;padding:20px;border-radius:12px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;padding:12px;border-bottom:1px solid #344457}th{color:#7ce2ca}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{overflow-wrap:anywhere}footer{margin-top:40px;color:#a5b2c7}</style><main>
<p>IRIS RECON / NETWORK INVENTORY</p><h1>Assessment report</h1>''' + (
        f'<div class="summary">{len(report["hosts"])} observed hosts · {open_count} explicitly open ports'
        f' · Run status: {"completed" if complete else "incomplete / unknown"}</div>'
        '<p>Service fingerprints are observations, not confirmed vulnerabilities. '
        'Confidence and identification method are supplied by Nmap. '
        'An open port alone does not establish a vulnerability.</p>'
        '<h2>Observed ports & services</h2><div class="scroll"><table><thead><tr>'
        '<th>Host</th><th>Port</th><th>State</th><th>Service evidence</th><th>Method</th><th>Confidence / 10</th>'
        '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'
        '<h2>Assessment follow-up</h2><p>Review whether observed services match the asset inventory, '
        'restrict unnecessary exposure, validate authentication and encryption, and confirm versions '
        'with the asset owner before researching applicable advisories.</p>'
        + changes + '<h2>Provenance</h2><p>Nmap ' + esc(report['nmap_version'])
        + ' · ' + esc(report['started']) + '</p><pre>' + esc(report['arguments'])
        + '</pre><p>Source XML SHA-256: <code>' + esc(report['source_sha256'])
        + '</code></p><footer>Generated locally by Iris Recon. Retain the original XML as evidence.</footer></main></html>')


def save_report(xml, out, baseline=None):
    report = parse_xml(xml)
    delta = compare(parse_xml(baseline), report) if baseline else None
    folder = Path(out)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'report.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    (folder / 'report.html').write_text(render_html(report, delta), encoding='utf-8')
    if delta is not None:
        (folder / 'changes.json').write_text(json.dumps(delta, indent=2), encoding='utf-8')
    return report


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
    sub = parser.add_subparsers(dest='action', required=True)
    offline = sub.add_parser('report', help='Analyze existing Nmap XML offline')
    offline.add_argument('xml')
    offline.add_argument('--out', default='assessment')
    offline.add_argument('--baseline', help='Previous Nmap XML to compare')
    scan = sub.add_parser('scan', help='Run Nmap on a declared authorized IP scope')
    scan.add_argument('target', help='IPv4/IPv6 address or CIDR; DNS names are not accepted')
    scan.add_argument('--scope', required=True, help='Authorized IP address or CIDR')
    scan.add_argument('--ports', default='22,80,443,445,3389,8080,8443')
    scan.add_argument('--max-rate', type=bounded_rate, default=100)
    scan.add_argument('--skip-discovery', action='store_true', help='Use -Pn if discovery is blocked')
    scan.add_argument('--out', required=True, help='New evidence directory; must not exist')
    scan.add_argument('--baseline')
    args = parser.parse_args(argv)
    try:
        if args.action == 'report':
            save_report(args.xml, args.out, args.baseline)
        else:
            executable = shutil.which('nmap')
            if not executable:
                raise ValueError('Nmap is not installed or is missing from PATH. Offline report mode remains available.')
            if args.baseline:
                parse_xml(args.baseline)
            folder = Path(args.out).resolve()
            xml = folder / 'scan.xml'
            cmd = scan_command(args, executable, xml)
            folder.mkdir(parents=True, exist_ok=False)
            (folder / 'command.json').write_text(json.dumps(cmd, indent=2), encoding='utf-8')
            print('Running:', subprocess.list2cmdline(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, shell=False)
            (folder / 'nmap.log').write_text(result.stdout + '\n' + result.stderr, encoding='utf-8')
            if result.returncode:
                raise ValueError(f'Nmap exited with {result.returncode}; inspect {folder / "nmap.log"}')
            save_report(xml, folder, args.baseline)
        print(f'Report saved to {Path(args.out).resolve() / "report.html"}')
        return 0
    except (ValueError, OSError, ET.ParseError, subprocess.SubprocessError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
