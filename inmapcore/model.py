"""Shared evidence and finding model. Severity means review priority."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

PRIORITIES = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}

STANDARDS = {
    'NET001': ('CWE-284', 'OWASP A01:2021'),
    'NET002': ('CWE-319', 'OWASP A02:2021'),
    'NET003': ('CWE-284', 'OWASP A05:2021'),
    'WEB001': ('CWE-16', 'OWASP A05:2021'),
    'WEB002': ('CWE-693', 'OWASP A05:2021'),
    'WEB003': ('CWE-200', 'OWASP A05:2021'),
    'WEB004': ('CWE-319', 'OWASP A02:2021'),
    'WEB005': ('CWE-319', 'OWASP A02:2021'),
    'WEB006': ('CWE-1021', 'OWASP A05:2021'),
    'WEB007': ('CWE-614', 'OWASP A05:2021'),
    'WEB008': ('CWE-942', 'OWASP A05:2021'),
    'WEB009': ('CWE-352', 'OWASP A07:2021'),
    'WEB010': ('CWE-307', 'OWASP A07:2021'),
    'TLS001': ('CWE-298', 'OWASP A02:2021'),
    'TLS002': ('CWE-326', 'OWASP A02:2021'),
    'SQL001': ('CWE-284', 'OWASP A04:2021'),
    'SQL002': ('CWE-200', 'OWASP A04:2021'),
    'SQL003': ('CWE-400', 'OWASP A04:2021'),
    'SQL004': ('CWE-284', 'OWASP A04:2021'),
    'SQL101': ('CWE-89', 'OWASP A03:2021'),
    'SQL102': ('CWE-89', 'OWASP A03:2021'),
    'SQL110': ('CWE-89', 'OWASP A03:2021'),
    'SQL201': ('CWE-89', 'OWASP A03:2021'),
    'DB001': ('CWE-1188', 'OWASP A04:2021'),
    'DB002': ('CWE-400', 'OWASP A04:2021'),
    'DB003': ('CWE-703', 'OWASP A05:2021'),
    'DB004': ('CWE-1188', 'OWASP A04:2021'),
    'DB005': ('CWE-400', 'OWASP A04:2021'),
    'CRED001': ('CWE-798', 'OWASP A07:2021'),
    'CRED002': ('CWE-798', 'OWASP A07:2021'),
    'CRYP001': ('CWE-328', 'OWASP A02:2021'),
    'CRYP002': ('CWE-338', 'OWASP A02:2021'),
    'CRYP003': ('CWE-295', 'OWASP A07:2021'),
    'SUB001': ('CWE-200', 'OWASP A05:2021'),
    'SUB002': ('CWE-284', 'OWASP A01:2021'),
    'DNS001': ('CWE-290', 'OWASP A05:2021'),
    'DNS002': ('CWE-290', 'OWASP A05:2021'),
    'DNS003': ('CWE-16', 'OWASP A05:2021'),
    'IAC001': ('CWE-250', 'OWASP A05:2021'),
    'IAC002': ('CWE-1188', 'OWASP A08:2021'),
    'IAC003': ('CWE-250', 'OWASP A05:2021'),
    'IAC004': ('CWE-798', 'OWASP A07:2021'),
    'CI001': ('CWE-276', 'OWASP A08:2021'),
    'CI002': ('CWE-829', 'OWASP A08:2021'),
    'CI003': ('CWE-78', 'OWASP A03:2021'),
    'DEP001': ('CWE-1395', 'OWASP A06:2021'),
    'DEP002': ('CWE-1188', 'OWASP A08:2021'),
}


def finding(rule, title, asset, severity, confidence, evidence, remediation, *, reference='', status='review'):
    identity = json.dumps([rule, str(asset), evidence], sort_keys=True, ensure_ascii=True)
    cwe, owasp = STANDARDS.get(rule, ('', ''))
    item = {'id': hashlib.sha256(identity.encode()).hexdigest()[:16], 'rule': rule,
            'title': title, 'asset': str(asset), 'severity': severity, 'confidence': confidence,
            'status': status, 'evidence': evidence, 'remediation': remediation, 'reference': reference}
    if cwe:
        item['cwe'] = cwe
    if owasp:
        item['owasp'] = owasp
    return item


def assessment(kind, title, *, findings=None, data=None, limitations=None):
    return {'schema_version': 2, 'kind': kind, 'title': title,
            'created_at': datetime.now(timezone.utc).isoformat(), 'status': 'completed',
            'findings': findings or [], 'data': data or {}, 'limitations': limitations or [],
            'sources': []}


def read_limited(path, limit=2 * 1024 * 1024):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f'{Path(path).name} exceeds the {limit // 1024} KiB input limit')
    return raw


def source_info(path, raw):
    return {'name': Path(path).name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
