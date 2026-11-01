"""Domain SPF, DMARC and CAA configuration review."""
import random
import re
import socket
import struct

from .model import assessment, finding

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$', re.I)


def _encode_qname(domain):
    parts = [p.encode('ascii') for p in domain.strip('.').split('.')]
    return b''.join(bytes([len(p)]) + p for p in parts) + b'\x00'


def _skip_name(buf, offset):
    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def query_dns_txt(name, nameserver='8.8.8.8', timeout=3.0):
    txid = random.randint(1, 65534)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(name) + struct.pack('!HH', 16, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + question, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return []
    finally:
        sock.close()
    if len(data) < 12:
        return []
    rxid, _, qdcount, ancount, _, _ = struct.unpack('!HHHHHH', data[:12])
    if rxid != txid:
        return []
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset) + 4
    records = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == 16:
            pos = 0
            chunks = []
            while pos < len(rdata):
                ln = rdata[pos]
                pos += 1
                chunks.append(rdata[pos:pos + ln].decode('utf-8', errors='replace'))
                pos += ln
            records.append(''.join(chunks))
    return records


def audit_dns(domain, txt_records=None, dmarc_records=None):
    clean = domain.strip().lower().strip('.')
    if not DOMAIN_RE.match(clean):
        raise ValueError(f'Invalid domain name: {domain}')
    root_txt = txt_records if txt_records is not None else query_dns_txt(clean)
    dmarc_txt = dmarc_records if dmarc_records is not None else query_dns_txt(f'_dmarc.{clean}')

    spf = [r for r in root_txt if r.lower().startswith('v=spf1')]
    dmarc = [r for r in dmarc_txt if r.lower().startswith('v=dmarc1')]
    findings = []

    if not spf:
        findings.append(finding('DNS001', 'No SPF record observed', clean, 'medium', 'high',
            {'domain': clean, 'txt_records_count': len(root_txt)},
            'Publish a v=spf1 TXT record listing authorized mail senders and ending with -all or ~all.'))
    else:
        joined = ' '.join(spf).lower()
        if '+all' in joined or '?all' in joined:
            findings.append(finding('DNS001', 'Permissive SPF policy qualifier observed', clean, 'high' if '+all' in joined else 'medium', 'high',
                {'spf': spf}, 'Replace +all or ?all with ~all (softfail) or -all (hardfail) after validating all legitimate senders.'))
        if len(spf) > 1:
            findings.append(finding('DNS001', 'Multiple SPF records observed', clean, 'medium', 'high',
                {'spf': spf}, 'Merge SPF mechanisms into a single v=spf1 record; RFC 7208 invalidates SPF when multiple records exist.'))

    if not dmarc:
        findings.append(finding('DNS002', 'No DMARC record observed', f'_dmarc.{clean}', 'medium', 'high',
            {'domain': f'_dmarc.{clean}'},
            'Publish a v=DMARC1 record at _dmarc with p=quarantine or p=reject and configure aggregate reporting (rua).'))
    else:
        record = dmarc[0]
        policy_match = re.search(r'\bp\s*=\s*([a-z]+)', record, re.I)
        policy = policy_match.group(1).lower() if policy_match else 'missing'
        if policy == 'none':
            findings.append(finding('DNS002', 'DMARC policy is set to monitor-only (p=none)', f'_dmarc.{clean}', 'low', 'high',
                {'dmarc': record, 'policy': policy},
                'After reviewing DMARC aggregate reports, transition policy to p=quarantine or p=reject to block spoofed messages.'))

    return assessment('dns', f'DNS & mail authentication review ({clean})', findings=findings,
        data={'domain': clean, 'spf': spf, 'dmarc': dmarc, 'root_txt': root_txt},
        limitations=[
            'Queries public TXT records for SPF and DMARC. DKIM selectors require known selector names from mail headers.',
            'Domains that never send mail should still publish v=spf1 -all and v=DMARC1; p=reject; to prevent spoofing.'])
