"""Shared evidence and finding model. Severity means review priority."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

PRIORITIES = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}


def finding(rule, title, asset, severity, confidence, evidence, remediation, *, reference='', status='review'):
    identity = json.dumps([rule, str(asset), evidence], sort_keys=True, ensure_ascii=True)
    return {
        'id': hashlib.sha256(identity.encode()).hexdigest()[:16],
        'rule': rule,
        'title': title,
        'asset': str(asset),
        'severity': severity,
        'confidence': confidence,
        'status': status,
        'evidence': evidence,
        'remediation': remediation,
        'reference': reference,
    }


def assessment(kind, title, *, findings=None, data=None, limitations=None):
    return {
        'schema_version': 2,
        'kind': kind,
        'title': title,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'status': 'completed',
        'findings': findings or [],
        'data': data or {},
        'limitations': limitations or [],
        'sources': [],
    }


def read_limited(path, limit=2 * 1024 * 1024):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f'{Path(path).name} exceeds the {limit // 1024} KiB input limit')
    return raw


def source_info(path, raw):
    return {
        'name': Path(path).name,
        'sha256': hashlib.sha256(raw).hexdigest(),
        'bytes': len(raw),
    }
