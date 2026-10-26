"""Nmap XML import and conservative observation comparison."""
import hashlib
import xml.etree.ElementTree as ET

from defusedxml.ElementTree import fromstring
from defusedxml.common import DefusedXmlException

from .model import assessment, finding, read_limited
from .reporting import render_assessment, save_assessment


def parse_xml(path):
    raw = read_limited(path, 32 * 1024 * 1024)
    try:
        root = fromstring(raw)
    except DefusedXmlException as exc:
        raise ValueError('XML entity or external declarations are unsupported') from exc
    if root.tag != 'nmaprun':
        raise ValueError('Expected an Nmap XML file')
    finished = root.find('runstats/finished')
    hosts = []
    for host in root.findall('host'):
        addresses = [a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6') and a.get('addr')]
        if not addresses:
            continue
        ports = []
        for port in host.findall('ports/port'):
            state, svc = port.find('state'), port.find('service')
            try:
                number = int(port.get('portid', ''))
            except ValueError as exc:
                raise ValueError('Invalid Nmap port number') from exc
            if not 0 <= number <= 65535 or port.get('protocol') not in ('tcp', 'udp', 'sctp', 'ip'):
                raise ValueError('Invalid port number or protocol in Nmap XML')
            ports.append({'port': number, 'protocol': port.get('protocol'),
                          'state': state.get('state', 'unknown') if state is not None else 'unknown',
                          'reason': state.get('reason', '') if state is not None else '',
                          'service': dict(svc.attrib) if svc is not None else {},
                          'cpe': [x.text for x in svc.findall('cpe')] if svc is not None else [],
                          'scripts': [dict(x.attrib) for x in port.findall('script')],
                          'script_details': [ET.tostring(x, encoding='unicode') for x in port.findall('script')]})
        status = host.find('status')
        hosts.append({'address': addresses[0], 'addresses': addresses,
                      'state': status.get('state', 'unknown') if status is not None else 'unknown',
                      'hostnames': [x.get('name', '') for x in host.findall('hostnames/hostname')],
                      'ports': sorted(ports, key=lambda p: (p['protocol'], p['port'])),
                      'extraports': [dict(x.attrib) for x in host.findall('ports/extraports')],
                      'host_scripts': [ET.tostring(x, encoding='unicode') for x in host.findall('hostscript/script')],
                      'os_matches': [dict(x.attrib) for x in host.findall('os/osmatch')]})
    return {'schema_version': 1, 'source_sha256': hashlib.sha256(raw).hexdigest(),
            'nmap_version': root.get('version', ''), 'arguments': root.get('args', ''),
            'started': root.get('startstr', root.get('start', '')),
            'scaninfo': [dict(x.attrib) for x in root.findall('scaninfo')],
            'finished': dict(finished.attrib) if finished is not None else {},
            'hosts': sorted(hosts, key=lambda h: h['address'])}


def coverage(report):
    result = {}
    for scan in report['scaninfo']:
        values = result.setdefault(scan.get('protocol', 'unknown'), set())
        for part in scan.get('services', '').split(','):
            if not part:
                continue
            try:
                bounds = [int(x) for x in part.split('-')]
            except ValueError:
                continue
            if len(bounds) in (1, 2) and 0 <= bounds[0] <= bounds[-1] <= 65535:
                values.update(range(bounds[0], bounds[-1] + 1))
    return result


def compare(before, after):
    def index(report):
        return {(h['address'], p['protocol'], p['port']): p for h in report['hosts'] for p in h['ports']}
    old, new = index(before), index(after)
    before_coverage, after_coverage = coverage(before), coverage(after)
    changes = []
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        if a is None:
            kind = 'newly_observed'
            interpretation = 'First explicit observation; not proof that the service was newly deployed.'
        elif b is None:
            kind = 'no_longer_observed'
            interpretation = ('Port was included in declared coverage, but no explicit result is present. Check host state, summarized ports and run completion.'
                              if key[2] in after_coverage.get(key[1], set()) else 'Port is outside or absent from current declared coverage.')
        elif any(a.get(k) != b.get(k) for k in ('state', 'service', 'cpe', 'scripts')):
            kind = 'changed'
            interpretation = f'Explicit states: {a["state"]} → {b["state"]}; service and script evidence may also differ.'
        else:
            continue
        changes.append({'address': key[0], 'protocol': key[1], 'port': key[2],
                        'change': kind, 'interpretation': interpretation, 'before': a, 'after': b})
    old_hosts = {h['address']: h for h in before['hosts']}
    new_hosts = {h['address']: h for h in after['hosts']}
    host_changes = []
    for address in sorted(old_hosts.keys() | new_hosts.keys()):
        if address not in old_hosts:
            change = 'newly_observed'
        elif address not in new_hosts:
            change = 'no_longer_observed'
        elif old_hosts[address]['state'] != new_hosts[address]['state']:
            change = f'{old_hosts[address]["state"]} → {new_hosts[address]["state"]}'
        else:
            continue
        host_changes.append({'address': address, 'change': change})
    return {'schema_version': 2,
            'warning': 'Absence is not proof of closure. Compare matching targets, ports and scan settings; discovery and filtering can change visibility.',
            'coverage_changed': before_coverage != after_coverage,
            'arguments_changed': before['arguments'] != after['arguments'],
            'before_completed': before['finished'].get('exit') == 'success',
            'after_completed': after['finished'].get('exit') == 'success',
            'host_changes': host_changes, 'changes': changes}


def network_assessment(raw, delta=None):
    report = assessment('network', 'Network exposure review', data=raw, limitations=[
        'Service fingerprints and open ports are observations, not confirmed vulnerabilities or CVE matches.',
        'Port-number-only service hints have low confidence. Verify the service, network reachability and intended access policy.',
        'Nmap may summarize uninteresting ports. Missing explicit entries are not labeled closed.'])
    report['status'] = 'completed' if raw['finished'].get('exit') == 'success' else 'incomplete / unknown'
    report['sources'] = [{'sha256': raw['source_sha256'], 'type': 'Nmap XML'}]
    db_ports = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
    db_names = {'mysql', 'postgresql', 'ms-sql-s', 'oracle', 'redis', 'mongodb', 'elasticsearch'}
    for host in raw['hosts']:
        for port in host['ports']:
            if port['state'] != 'open':
                continue
            svc = port['service']
            name = svc.get('name', '')
            asset = f'{host["address"]}:{port["port"]}/{port["protocol"]}'
            evidence = {'state': port['state'], 'service': svc, 'cpe': port['cpe']}
            if name in db_names or port['port'] in db_ports:
                report['findings'].append(finding('NET001', 'Review reachable database or data-store endpoint', asset,
                    'medium', 'medium' if name in db_names and svc.get('method') == 'probed' else 'low', evidence,
                    'Verify the service and allowed clients. Restrict network access, require authentication and encryption, and review database privileges. An open port does not establish unauthorized access.'))
            if name in ('telnet', 'ftp', 'pop3', 'imap') and svc.get('tunnel') != 'ssl':
                report['findings'].append(finding('NET002', 'Review transport protection for this service', asset,
                    'medium', 'medium', evidence,
                    'Confirm whether TLS or STARTTLS is required before credentials are accepted. Replace plaintext-only services or restrict them to an appropriate protected network.'))
    if delta is not None:
        report['comparison'] = delta
    return report


def render_html(raw, delta=None):
    return render_assessment(network_assessment(raw, delta))


def save_report(xml, out, baseline=None):
    raw = parse_xml(xml)
    delta = compare(parse_xml(baseline), raw) if baseline else None
    report = network_assessment(raw, delta)
    save_assessment(report, out)
    return report
