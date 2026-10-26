"""Passive Certificate Transparency (crt.sh) reconnaissance and DNS attack surface mapping."""
import asyncio
import json
import re
import socket
import urllib.request
import urllib.error
from typing import Dict, Any, List, Set

from .model import assessment, finding
from .intel import classify_ip

SENSITIVE_SUBDOMAIN_PATTERNS = [
    (re.compile(r'^(dev|devel|development|staging|stage|stg|test|testing|qa|uat|sandbox|demo)\.', re.I),
     'Exposed pre-production or staging environment', 'medium', 'SUB001',
     'Pre-production environments often have weaker access controls, verbose debugging or mock credentials. Restrict public DNS or enforce IP allow-lists/VPN access.'),
    (re.compile(r'^(admin|adm|portal|manage|manager|cpanel|whm|webmail|vpn|remote|bastion|internal|corp|ldap|sso|auth|kibana|grafana|prometheus|jenkins|gitlab|git)\.', re.I),
     'Exposed administrative or internal management service', 'high', 'SUB002',
     'Administrative interfaces should not be publicly discoverable without mutual TLS, VPN, or zero-trust identity proxy protection.')
]


def query_crt_sh(domain: str, timeout: float = 12.0) -> List[str]:
    """Query Certificate Transparency logs via crt.sh without external third-party libraries."""
    clean_domain = domain.strip().lower().lstrip('.')
    url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) INMAP/1.0.0 Recon'}

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return []
            raw = resp.read(8 * 1024 * 1024)
            data = json.loads(raw.decode('utf-8', errors='replace'))
    except Exception:
        # Fallback if crt.sh is slow or rate-limited
        return []

    subdomains: Set[str] = set()
    for entry in data:
        for key in ('name_value', 'common_name'):
            val = entry.get(key)
            if not val:
                continue
            for item in val.split('\n'):
                item = item.strip().lower()
                if item.startswith('*.'):
                    item = item[2:]
                if item and (item == clean_domain or item.endswith('.' + clean_domain)):
                    subdomains.add(item)

    return sorted(list(subdomains))


async def resolve_subdomain(subdomain: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
    """Resolve a subdomain to A and AAAA addresses using non-blocking getaddrinfo."""
    loop = asyncio.get_running_loop()
    ips = set()
    async with semaphore:
        try:
            addr_info = await loop.getaddrinfo(subdomain, None, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                ips.add(ip_str)
        except Exception:
            pass

    resolved_list = sorted(list(ips))
    intel_records = [classify_ip(ip) for ip in resolved_list]

    return {
        'subdomain': subdomain,
        'resolved': bool(resolved_list),
        'ips': resolved_list,
        'intel': intel_records
    }


def audit_subdomains(domain: str, known_subdomains: Optional[List[str]] = None, resolve_dns: bool = True) -> Dict[str, Any]:
    """Run Certificate Transparency subdomain enumeration and DNS mapping."""
    clean_domain = domain.strip().lower().lstrip('.')
    if not clean_domain or '.' not in clean_domain:
        raise ValueError(f"Invalid domain name: '{domain}'")

    if known_subdomains is None:
        subdomain_list = query_crt_sh(clean_domain)
    else:
        subdomain_list = sorted(list(set(known_subdomains)))

    # Ensure apex domain is included
    if clean_domain not in subdomain_list:
        subdomain_list.append(clean_domain)

    subdomain_records = []
    if resolve_dns and subdomain_list:
        async def _resolve_all():
            sem = asyncio.Semaphore(50)
            tasks = [resolve_subdomain(s, sem) for s in subdomain_list]
            return await asyncio.gather(*tasks)

        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            subdomain_records = loop.run_until_complete(_resolve_all())
        finally:
            loop.close()
    else:
        for s in subdomain_list:
            subdomain_records.append({
                'subdomain': s,
                'resolved': False,
                'ips': [],
                'intel': []
            })

    # Findings generation
    findings = []
    for rec in subdomain_records:
        sub = rec['subdomain']
        has_ips = rec['resolved']
        ips = rec['ips']

        # Check for sensitive prefixes
        for pattern, title, severity, rule_code, remediation in SENSITIVE_SUBDOMAIN_PATTERNS:
            if pattern.search(sub):
                evidence = {
                    'subdomain': sub,
                    'resolved_ips': ips,
                    'intel': rec['intel']
                }
                findings.append(finding(
                    rule_code,
                    title,
                    sub,
                    severity if has_ips else 'low',
                    'high' if has_ips else 'medium',
                    evidence,
                    remediation
                ))

        # Check for dangling or unresolvable CT record if it had an apex
        if not has_ips and sub != clean_domain and not resolve_dns:
            pass

    report = assessment(
        kind='subdomains',
        title=f"Attack Surface Reconnaissance ({clean_domain})",
        findings=findings,
        data={
            'domain': clean_domain,
            'total_subdomains_discovered': len(subdomain_list),
            'resolved_active_subdomains': sum(1 for r in subdomain_records if r['resolved']),
            'records': subdomain_records
        },
        limitations=[
            'Passive Certificate Transparency reflects certificates issued historically; expired certs or decommissioned hosts may appear.',
            'Wildcard DNS may resolve non-existent subdomains to a default IP; verify actual HTTP/service response.',
            'Private or internal subdomains not requesting public TLS certs will not appear in crt.sh.'
        ]
    )
    return report
