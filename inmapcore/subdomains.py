"""Passive Certificate Transparency (crt.sh) lookup and DNS resolution."""
import asyncio
import json
import re
import socket
import urllib.request

from .intel import classify_ip
from .model import assessment, finding

PATTERNS = [
    (re.compile(r'^(dev|devel|development|staging|stage|stg|test|testing|qa|uat|sandbox|demo)\.', re.I),
     'Pre-production or staging subdomain observed', 'medium', 'SUB001',
     'Pre-production environments often have weaker access controls or debug settings. Restrict network reachability or require VPN/SSO.'),
    (re.compile(r'^(admin|adm|portal|manage|manager|cpanel|whm|webmail|vpn|remote|bastion|internal|corp|ldap|sso|auth|kibana|grafana|prometheus|jenkins|gitlab|git)\.', re.I),
     'Administrative or internal service subdomain observed', 'high', 'SUB002',
     'Verify that administrative interfaces require strong authentication, MFA and network access restrictions.'),
]


def query_crt_sh(domain, timeout=12.0):
    clean = domain.strip().lower().lstrip('.')
    url = f'https://crt.sh/?q=%.{clean}&output=json'
    req = urllib.request.Request(url, headers={'User-Agent': 'INMAP/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return []
            raw = resp.read(8 * 1024 * 1024)
            data = json.loads(raw.decode('utf-8', errors='replace'))
    except Exception:
        return []

    subdomains = set()
    for entry in data:
        for key in ('name_value', 'common_name'):
            val = entry.get(key)
            if not val:
                continue
            for item in val.split('\n'):
                item = item.strip().lower()
                if item.startswith('*.'):
                    item = item[2:]
                if item and (item == clean or item.endswith('.' + clean)):
                    subdomains.add(item)
    return sorted(subdomains)


async def resolve_subdomain(subdomain, semaphore):
    loop = asyncio.get_running_loop()
    ips = set()
    async with semaphore:
        try:
            infos = await loop.getaddrinfo(subdomain, None, proto=socket.IPPROTO_TCP)
            for item in infos:
                ips.add(item[4][0])
        except Exception:
            pass
    resolved_list = sorted(ips)
    return {
        'subdomain': subdomain,
        'resolved': bool(resolved_list),
        'ips': resolved_list,
        'intel': [classify_ip(ip) for ip in resolved_list],
    }


def audit_subdomains(domain, known_subdomains=None, resolve_dns=True):
    clean = domain.strip().lower().lstrip('.')
    if not clean or '.' not in clean:
        raise ValueError(f'Invalid domain name: {domain}')

    subdomain_list = sorted(set(known_subdomains)) if known_subdomains is not None else query_crt_sh(clean)
    if clean not in subdomain_list:
        subdomain_list.append(clean)

    records = []
    if resolve_dns and subdomain_list:
        async def _resolve_all():
            sem = asyncio.Semaphore(50)
            return await asyncio.gather(*(resolve_subdomain(s, sem) for s in subdomain_list))

        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            records = loop.run_until_complete(_resolve_all())
        finally:
            loop.close()
    else:
        records = [{'subdomain': s, 'resolved': False, 'ips': [], 'intel': []} for s in subdomain_list]

    findings = []
    for rec in records:
        sub = rec['subdomain']
        has_ips = rec['resolved']
        for pattern, title, severity, rule_code, remediation in PATTERNS:
            if pattern.search(sub):
                findings.append(finding(rule_code, title, sub,
                    severity if has_ips else 'low', 'high' if has_ips else 'medium',
                    {'subdomain': sub, 'resolved_ips': rec['ips'], 'intel': rec['intel']},
                    remediation))

    return assessment('subdomains', f'Subdomain & DNS review ({clean})', findings=findings,
        data={'domain': clean, 'total_subdomains_discovered': len(subdomain_list),
              'resolved_active_subdomains': sum(1 for r in records if r['resolved']), 'records': records},
        limitations=[
            'Certificate Transparency logs include historical and expired certificates.',
            'Wildcard DNS records may resolve arbitrary subdomains to a default gateway IP.',
            'Internal hosts without public certificates are not present in CT logs.'])
