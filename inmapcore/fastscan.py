"""Asynchronous TCP port scanner and banner probe."""
import asyncio
import ipaddress
import time

from .intel import classify_ip
from .model import assessment, finding

KNOWN_SERVICES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
    1433: 'ms-sql-s', 1521: 'oracle', 3306: 'mysql', 3389: 'ms-wbt-server',
    5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8000: 'http-alt',
    8080: 'http-proxy', 8443: 'https-alt', 8888: 'http-alt', 9200: 'elasticsearch',
    27017: 'mongodb',
}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
PLAINTEXT_PORTS = {21: 'ftp', 23: 'telnet', 110: 'pop3', 143: 'imap', 5900: 'vnc'}


async def grab_banner(host, port, timeout=1.5):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return ''
    banner = ''
    try:
        if port in (80, 8080, 8000, 8888):
            writer.write(b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
            await writer.drain()
        elif port == 6379:
            writer.write(b'PING\r\n')
            await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        banner = data.decode('latin1', errors='replace').strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return banner


async def probe_port(host, port, timeout, semaphore):
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
        except Exception:
            return None

    banner = await grab_banner(host, port, timeout=min(timeout, 1.5))
    service_name = KNOWN_SERVICES.get(port, 'unknown')
    product = ''
    if 'SSH-' in banner:
        service_name = 'ssh'
        product = banner.split('\n')[0].strip()
    elif 'Server:' in banner:
        service_name = 'http' if port != 443 else 'https'
        for line in banner.splitlines():
            if line.lower().startswith('server:'):
                product = line.split(':', 1)[1].strip()
                break
    elif banner.startswith(('+PONG', '-NOAUTH', '-ERR')):
        service_name, product = 'redis', 'Redis'
    elif 'mysql' in banner.lower() or 'mariadb' in banner.lower():
        service_name, product = 'mysql', 'MySQL / MariaDB'

    return {
        'port': port,
        'protocol': 'tcp',
        'state': 'open',
        'reason': 'syn-ack-or-connected',
        'service': {
            'name': service_name,
            'product': product,
            'version': '',
            'banner': banner[:200] if banner else '',
            'method': 'banner-probe' if banner else 'port-lookup',
            'conf': 8 if banner else 3,
        },
        'cpe': [],
        'scripts': [],
    }


async def scan_host(host_ip, ports, timeout=1.5, concurrency=100):
    semaphore = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*(probe_port(host_ip, p, timeout, semaphore) for p in ports))
    open_ports = sorted((r for r in results if r is not None), key=lambda p: p['port'])
    return {
        'address': host_ip,
        'addresses': [host_ip],
        'state': 'up' if open_ports else 'down_or_unreachable',
        'hostnames': [],
        'intel': classify_ip(host_ip),
        'ports': open_ports,
        'extraports': [],
        'host_scripts': [],
        'os_matches': [],
    }


def parse_port_list(ports_spec):
    result = set()
    for part in ports_spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start_s, end_s = part.split('-', 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f'Invalid port range: {part}')
            if end - start > 10000:
                raise ValueError('Port range span cannot exceed 10000 ports')
            result.update(range(start, end + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f'Port {p} out of range (1..65535)')
            result.add(p)
    return sorted(result)


def run_fast_scan(target_spec, scope_spec, ports_spec, max_rate=100, timeout=1.5):
    target_net = ipaddress.ip_network(target_spec, strict=False)
    scope_net = ipaddress.ip_network(scope_spec, strict=False)
    if target_net.version != scope_net.version or not target_net.subnet_of(scope_net):
        raise ValueError('Target must be inside the declared authorized scope')
    if target_net.num_addresses > 1024:
        raise ValueError('Native scanner supports at most 1024 addresses per run')

    port_list = parse_port_list(ports_spec)
    concurrency = min(max_rate, 250)
    if target_net.num_addresses == 1:
        hosts_to_scan = [str(target_net.network_address)]
    elif target_net.version == 4 and target_net.prefixlen < 31:
        hosts_to_scan = [str(ip) for ip in list(target_net.hosts())[:1024]]
    else:
        hosts_to_scan = [str(ip) for ip in list(target_net)[:1024]]

    started = time.monotonic()

    async def _runner():
        return await asyncio.gather(*(scan_host(h, port_list, timeout=timeout, concurrency=concurrency) for h in hosts_to_scan))

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        host_results = loop.run_until_complete(_runner())
    finally:
        loop.close()

    elapsed = round(time.monotonic() - started, 2)
    findings = []
    for h in host_results:
        addr = h['address']
        intel = h.get('intel', {})
        is_public = not intel.get('is_private') and not intel.get('is_loopback')
        for p in h['ports']:
            port_num = p['port']
            svc = p['service']
            name = svc.get('name', 'unknown')
            asset = f'{addr}:{port_num}/tcp'
            evidence = {'port': port_num, 'service': svc, 'intel': intel}
            if port_num in DATABASE_PORTS or name in ('mysql', 'postgresql', 'redis', 'mongodb', 'ms-sql-s', 'oracle', 'elasticsearch'):
                findings.append(finding('NET001', 'Reachable database or data-store port', asset,
                    'high' if is_public else 'medium',
                    'high' if svc.get('method') == 'banner-probe' else 'medium', evidence,
                    f'Restrict inbound access to port {port_num} via firewall rules and require authenticated TLS connections.'))
            if port_num in PLAINTEXT_PORTS:
                proto_label = PLAINTEXT_PORTS[port_num].upper()
                findings.append(finding('NET002', f'Unencrypted transport service observed ({proto_label})', asset,
                    'medium', 'high', evidence,
                    f'Replace plaintext {proto_label} with an encrypted protocol alternative or restrict access to a local administrative subnet.'))
            if port_num == 3389:
                findings.append(finding('NET003', 'Reachable Remote Desktop (RDP) endpoint', asset,
                    'high' if is_public else 'medium', 'medium', evidence,
                    'Place RDP behind a VPN, bastion host or identity-aware proxy with multi-factor authentication.'))

    return assessment('network', f'Network exposure review ({target_spec})', findings=findings,
        data={'scanner': 'INMAP Async TCP', 'elapsed_seconds': elapsed, 'target': target_spec,
              'scope': scope_spec, 'ports_scanned': len(port_list), 'hosts_scanned': len(hosts_to_scan),
              'hosts': host_results, 'finished': {'exit': 'success'}},
        limitations=[
            'Checks TCP connect reachability and initial service banners.',
            'Silently dropped packets are recorded as unreachable after timeout.',
            'Open ports and banners are observations, not confirmed vulnerabilities.'])
