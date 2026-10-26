"""Native asynchronous TCP port scanner and service banner grabber."""
import asyncio
import ipaddress
import socket
import time
from typing import List, Dict, Any, Optional

from .model import assessment, finding
from .intel import classify_ip

KNOWN_SERVICES = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
    1433: 'ms-sql-s', 1521: 'oracle', 3306: 'mysql', 3389: 'ms-wbt-server',
    5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8000: 'http-alt',
    8080: 'http-proxy', 8443: 'https-alt', 8888: 'http-alt', 9200: 'elasticsearch',
    27017: 'mongodb'
}

DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
PLAINTEXT_PORTS = {21: 'ftp', 23: 'telnet', 110: 'pop3', 143: 'imap', 5900: 'vnc'}


async def grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """Politely read initial banner or send minimal probe."""
    banner = ''
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
    except Exception:
        return ''

    try:
        # For HTTP ports, send a quick HTTP/1.0 HEAD request
        if port in (80, 8080, 8000, 8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
        elif port == 6379:
            writer.write(b"PING\r\n")
            await writer.drain()

        # Read banner up to 512 bytes with timeout
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


async def probe_port(host: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    """Probe a single TCP port using non-blocking connection."""
    async with semaphore:
        try:
            # First attempt connection check
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            await writer.wait_closed()
        except Exception:
            return None

    # Port is open, attempt banner grab
    banner = await grab_banner(host, port, timeout=min(timeout, 1.5))
    service_name = KNOWN_SERVICES.get(port, 'unknown')
    product = ''
    version = ''

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
        service_name = 'redis'
        product = 'Redis'
    elif 'mysql' in banner.lower() or (len(banner) > 4 and 'mariadb' in banner.lower()):
        service_name = 'mysql'
        product = 'MySQL / MariaDB'

    return {
        'port': port,
        'protocol': 'tcp',
        'state': 'open',
        'reason': 'syn-ack-or-connected',
        'service': {
            'name': service_name,
            'product': product,
            'version': version,
            'banner': banner[:200] if banner else '',
            'method': 'banner-probe' if banner else 'port-lookup',
            'conf': 8 if banner else 3
        },
        'cpe': [],
        'scripts': []
    }


async def scan_host(host_ip: str, ports: List[int], timeout: float = 1.5, concurrency: int = 100) -> Dict[str, Any]:
    """Scan a list of ports on a specific IP."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [probe_port(host_ip, port, timeout, semaphore) for port in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [r for r in results if r is not None]
    open_ports.sort(key=lambda p: p['port'])

    intel = classify_ip(host_ip)

    return {
        'address': host_ip,
        'addresses': [host_ip],
        'state': 'up' if open_ports else 'down_or_unreachable',
        'hostnames': [],
        'intel': intel,
        'ports': open_ports,
        'extraports': [],
        'host_scripts': [],
        'os_matches': []
    }


def parse_port_list(ports_spec: str) -> List[int]:
    """Parse port string like '22,80,443' or '1-1024' into list of unique ints."""
    result = set()
    for part in ports_spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start_str, end_str = part.split('-', 1)
            start, end = int(start_str), int(end_str)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Invalid port range '{part}'")
            if end - start > 10000:
                raise ValueError("Port range span cannot exceed 10000 ports in single scan")
            result.update(range(start, end + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"Port {p} out of range (1..65535)")
            result.add(p)
    return sorted(list(result))


def run_fast_scan(target_spec: str, scope_spec: str, ports_spec: str, max_rate: int = 100, timeout: float = 1.5) -> Dict[str, Any]:
    """Execute asynchronous native scan and return INMAP assessment dict."""
    target_net = ipaddress.ip_network(target_spec, strict=False)
    scope_net = ipaddress.ip_network(scope_spec, strict=False)

    if target_net.version != scope_net.version or not target_net.subnet_of(scope_net):
        raise ValueError('Target must be inside the declared authorized scope')
    if target_net.num_addresses > 1024:
        raise ValueError('Native scanner supports at most 1024 addresses per batch')

    port_list = parse_port_list(ports_spec)
    concurrency = min(max_rate, 250)

    # Gather hosts to scan
    if target_net.num_addresses == 1:
        hosts_to_scan = [str(target_net.network_address)]
    else:
        # Exclude network and broadcast if IPv4 and prefix < 31
        if target_net.version == 4 and target_net.prefixlen < 31:
            hosts_to_scan = [str(ip) for ip in list(target_net.hosts())[:1024]]
        else:
            hosts_to_scan = [str(ip) for ip in list(target_net)[:1024]]

    start_time = time.time()

    async def _runner():
        host_tasks = [scan_host(h, port_list, timeout=timeout, concurrency=concurrency) for h in hosts_to_scan]
        return await asyncio.gather(*host_tasks)

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        host_results = loop.run_until_complete(_runner())
    finally:
        loop.close()

    elapsed = round(time.time() - start_time, 2)

    # Synthesize assessment
    findings = []
    for h in host_results:
        addr = h['address']
        intel = h.get('intel', {})
        is_public = not intel.get('is_private', False) and not intel.get('is_loopback', False)

        for p in h['ports']:
            port_num = p['port']
            svc = p['service']
            name = svc.get('name', 'unknown')
            asset = f"{addr}:{port_num}/tcp"
            evidence = {'port': port_num, 'service': svc, 'intel': intel}

            if port_num in DATABASE_PORTS or name in ('mysql', 'postgresql', 'redis', 'mongodb', 'ms-sql-s', 'oracle', 'elasticsearch'):
                severity = 'high' if is_public else 'medium'
                findings.append(finding(
                    'NET001',
                    'Direct database or datastore port exposed',
                    asset,
                    severity,
                    'high' if svc.get('method') == 'banner-probe' else 'medium',
                    evidence,
                    f"Restrict inbound access to port {port_num} via firewall / security groups. Database endpoints should reside in private subnets with mutual TLS and strict role-based access control."
                ))

            if port_num in PLAINTEXT_PORTS:
                findings.append(finding(
                    'NET002',
                    f"Plaintext or unencrypted transport service observed ({PLAINTEXT_PORTS[port_num].upper()})",
                    asset,
                    'medium',
                    'high',
                    evidence,
                    f"Replace unencrypted {PLAINTEXT_PORTS[port_num].upper()} with an encrypted protocol alternative (e.g., SFTP/SSH, FTPS, IMAPS) or disable the service entirely."
                ))

            if port_num == 3389:
                findings.append(finding(
                    'NET003',
                    'Exposed Remote Desktop Protocol (RDP) endpoint',
                    asset,
                    'high' if is_public else 'medium',
                    'medium',
                    evidence,
                    "Place RDP services behind an authenticated VPN, Identity-Aware Proxy (IAP), or Bastion host with multi-factor authentication (MFA)."
                ))

    raw_data = {
        'scanner': 'INMAP Native Async Engine',
        'elapsed_seconds': elapsed,
        'target': target_spec,
        'scope': scope_spec,
        'ports_scanned': len(port_list),
        'hosts_scanned': len(hosts_to_scan),
        'hosts': host_results,
        'finished': {'exit': 'success'}
    }

    report = assessment(
        kind='network',
        title=f"Native Network Assessment ({target_spec})",
        findings=findings,
        data=raw_data,
        limitations=[
            'Native asynchronous scanner verifies TCP SYN/connect reachability and banner response.',
            'Firewalls dropping packets (silently dropping RST/SYN-ACK) are treated as closed or filtered after timeout.',
            'Non-standard services on arbitrary ports require deep banner inspection.'
        ]
    )
    return report
