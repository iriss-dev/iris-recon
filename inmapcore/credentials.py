"""Local credential discovery and keyed comparison across assessments."""
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
from urllib.parse import unquote, urlsplit

from .model import assessment, finding, read_limited

SECRET_KEY = re.compile(r'(?:^|[_-])(password|passwd|pwd|secret|token|api_key|apikey|access_key|client_secret)$', re.I)
USER_KEY = re.compile(r'(?:^|[_-])(username|user|login)$', re.I)
ASSIGNMENT = re.compile(r'''^\s*(?:export\s+)?["']?([\w.-]+)["']?\s*[:=]\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s#,;]+))''')
URL = re.compile(r'\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql)://[^\s"\'<>]+', re.I)
TOKEN_SIGNATURES = [
    ('aws_access_key', re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ('github_token', re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b')),
    ('stripe_secret', re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,99})\b')),
    ('slack_token', re.compile(r'\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b')),
    ('private_key', re.compile(r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)')),
]
PLACEHOLDERS = {'', 'changeme', 'change_me', 'your_password', 'password_here', 'example', 'redacted', 'null', 'none', 'undefined', 'true', 'false'}


def shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 2)


def real_value(value):
    return value.lower() not in PLACEHOLDERS and not any(x in value for x in ('${', '{{', '<password', '<token'))


def load_key(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        key = read_limited(path, 32)
    else:
        key = secrets.token_bytes(32)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(key)
    if len(key) != 32:
        raise ValueError('Credential comparison key must contain exactly 32 bytes')
    return key


def prefix(name, pattern):
    match = pattern.search(name)
    return name[:match.start()].lower() if match else name.lower()


def extract(text, suffix):
    records = []
    seen_values = set()
    if suffix == '.json':
        def walk(value, pointer='$'):
            if isinstance(value, dict):
                users = {prefix(k, USER_KEY): str(v) for k, v in value.items() if USER_KEY.search(k) and isinstance(v, (str, int))}
                for k, v in value.items():
                    if SECRET_KEY.search(k) and isinstance(v, str) and real_value(v):
                        records.append({'key': pointer + '.' + k, 'line': None, 'username': users.get(prefix(k, SECRET_KEY)), 'value': v, 'method': 'JSON literal and sibling username'})
                        seen_values.add(v)
                    walk(v, pointer + '.' + k)
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    walk(v, f'{pointer}[{i}]')
        walk(json.loads(text))
    else:
        assignments = []
        section = ''
        for line, content in enumerate(text.splitlines(), 1):
            if content.lstrip().startswith(('#', '//', ';')):
                continue
            if re.fullmatch(r'\s*\[[^\]]+\]\s*', content):
                section = content.strip()
            match = ASSIGNMENT.match(content)
            if match:
                value = next(v for v in match.groups()[1:] if v is not None)
                if suffix in ('.py', '.js', '.ts') and match.group(4) is not None:
                    continue
                assignments.append((match.group(1), value, line, section))
        for name, value, line, section in assignments:
            if not SECRET_KEY.search(name) or not real_value(value):
                continue
            users = [(abs(line - pos), val) for key, val, pos, group in assignments
                     if group == section and USER_KEY.search(key) and prefix(key, USER_KEY) == prefix(name, SECRET_KEY)]
            records.append({'key': section + name, 'line': line, 'username': min(users)[1] if users else None,
                            'value': value, 'method': 'literal assignment; nearest matching username key in same section'})
            seen_values.add(value)
    for match in URL.finditer(text):
        parsed = urlsplit(match.group())
        if parsed.password and real_value(unquote(parsed.password)):
            val = unquote(parsed.password)
            records.append({'key': f'connection:{parsed.scheme}://{parsed.hostname}{parsed.path}',
                            'line': text.count('\n', 0, match.start()) + 1,
                            'username': unquote(parsed.username or ''), 'value': val,
                            'method': 'database connection URL'})
            seen_values.add(val)
    for kind, pattern in TOKEN_SIGNATURES:
        for match in pattern.finditer(text):
            val = match.group(1)
            if val in seen_values:
                continue
            line_no = text.count('\n', 0, match.start()) + 1
            line_str = text.splitlines()[line_no - 1] if line_no <= len(text.splitlines()) else ''
            if line_str.lstrip().startswith(('#', '//', ';')):
                continue
            records.append({'key': f'signature:{kind}', 'line': line_no, 'username': None,
                            'value': val, 'method': f'token signature ({kind}, entropy={shannon_entropy(val)})'})
            seen_values.add(val)
    return records


def audit_credentials(path, key_file, baseline=None, reveal=False):
    root = Path(path).resolve(strict=True)
    key_path = Path(key_file).resolve()
    key = load_key(key_path)
    key_id = hashlib.sha256(key).hexdigest()[:16]
    prior = {}
    if baseline:
        previous = json.loads(read_limited(baseline, 32 * 1024 * 1024))
        if previous.get('kind') != 'credentials' or previous.get('data', {}).get('key_id') != key_id:
            raise ValueError('Baseline must be a credential report generated with the same comparison key')
        prior = {r['identity']: r for r in previous['data']['credentials']}
    report = assessment('credentials', 'Credential exposure review', limitations=[
        'Inspects only literal credentials in local files and database connection URLs. It never tries to log in or extract accounts from a remote database.',
        'Username association is best-effort context. Confirm the relevant application and account before rotating credentials.',
        'Unchanged means the same literal remains in the inspected file. Changed means the literal differs; neither proves which password the server currently accepts.',
        'A credential no longer observed may have moved, become unreadable or left the selected scope. It is not proof of revocation.',
        'HMAC fingerprints use a local random key. Keep the key private and reuse it for comparisons. Passwords are masked unless reveal mode was explicitly requested.'])
    report['data'] = {'key_id': key_id, 'reveal_secrets': reveal, 'credentials': [], 'files': [],
                      'scope': root.name, 'scope_kind': 'file' if root.is_file() else 'directory'}
    if baseline:
        report['data']['baseline_scope_changed'] = (previous['data'].get('scope') != root.name or previous['data'].get('scope_kind') != report['data']['scope_kind'])
    extensions = {'.json', '.yaml', '.yml', '.ini', '.toml', '.cfg', '.conf', '.properties', '.py', '.js', '.ts', '.env', '.pem', '.key'}
    ignored = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'reports', 'work', 'demo', 'dist', 'build'}
    paths = [root] if root.is_file() else []
    if root.is_dir():
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in ignored and not (Path(current) / d).is_symlink())
            paths.extend(Path(current) / f for f in sorted(files) if (Path(f).suffix.lower() in extensions or f.startswith('.env')) and not (Path(current) / f).is_symlink())
            if len(paths) > 500:
                raise ValueError('Credential assessment is limited to 500 files; choose a smaller directory')
    total = 0
    identities = set()
    for path in paths:
        if path.resolve() == key_path or (baseline and path.resolve() == Path(baseline).resolve()):
            continue
        asset = path.name if root.is_file() else path.relative_to(root).as_posix()
        try:
            raw = read_limited(path, 1024 * 1024)
            total += len(raw)
            if total > 20 * 1024 * 1024:
                raise ValueError('Credential assessment exceeds 20 MiB')
            entries = extract(raw.decode('utf-8-sig'), path.suffix.lower())
            report['sources'].append({'name': asset, 'bytes': len(raw),
                                      'hmac_sha256': hmac.new(key, raw, hashlib.sha256).hexdigest()})
            report['data']['files'].append({'name': asset, 'status': 'analyzed', 'findings': len(entries)})
        except (UnicodeError, json.JSONDecodeError, OSError):
            report['status'] = 'partial'
            report['data']['files'].append({'name': asset, 'status': 'not analyzed'})
            continue
        occurrences = {}
        for entry in entries:
            occurrences[entry['key']] = occurrences.get(entry['key'], 0) + 1
            identity = hashlib.sha256(json.dumps([asset, entry['key'], occurrences[entry['key']]]).encode()).hexdigest()[:24]
            fingerprint = hmac.new(key, entry['value'].encode(), hashlib.sha256).hexdigest()
            old = prior.get(identity)
            change = 'not_compared' if not baseline else 'newly_observed'
            if old:
                change = 'unchanged' if hmac.compare_digest(fingerprint, old['fingerprint']) else 'changed'
            item = {'identity': identity, 'file': asset, 'key': entry['key'], 'line': entry['line'],
                    'username': entry['username'], 'password_or_secret': entry['value'] if reveal else '[masked]',
                    'fingerprint': fingerprint, 'comparison': change, 'method': entry['method'],
                    'entropy': shannon_entropy(entry['value']),
                    'username_changed': old is not None and old.get('username') != entry['username']}
            report['data']['credentials'].append(item)
            identities.add(identity)
            rule = 'CRED002' if entry['key'].startswith('signature:') else 'CRED001'
            severity = 'high' if rule == 'CRED002' else 'medium'
            report['findings'].append(finding(rule, 'Credential or token literal found in a local file',
                f'{asset}:{entry["line"] or entry["key"]}', severity, 'high' if rule == 'CRED002' else 'medium', item,
                'Verify the associated account. If this value was exposed, rotate it at the service and update the application secret store. Remove the literal from source; file changes alone do not revoke an old credential.', status='potential'))
    report['data']['no_longer_observed'] = [
        {k: r.get(k) for k in ('identity', 'file', 'key', 'username', 'fingerprint')}
        for identity, r in prior.items() if identity not in identities]
    return report
