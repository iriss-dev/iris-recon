"""Container, CI/CD workflow and cryptographic configuration review."""
import os
from pathlib import Path
import re

from .model import assessment, finding, read_limited, source_info

FROM_RE = re.compile(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', re.I)
USER_RE = re.compile(r'^\s*USER\s+(\S+)', re.I)
ENV_SECRET_RE = re.compile(r'^\s*(?:ENV|ARG)\s+([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)', re.I)
USES_RE = re.compile(r'^\s*-?\s*uses:\s*["\']?([^"\'\s#]+)', re.I)
UNTRUSTED_EXPR = re.compile(r'\$\{\{\s*github\.(?:head_ref|event\.(?:issue|pull_request|comment|review|discussion|pages|commits)\.[^}]*(?:title|body|message|ref|name))', re.I)
WEAK_HASH_RE = re.compile(r'\b(?:hashlib\.(?:md5|sha1)|createHash\s*\(\s*["\'](?:md5|sha1)["\'])\b')
NO_VERIFY_RE = re.compile(r'(?:\bverify\s*=\s*False\b|\bCERT_NONE\b|\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0)')


def check_dockerfile(text, asset):
    findings = []
    last_user = None
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        m_from = FROM_RE.match(line)
        if m_from:
            image = m_from.group(1)
            if image.lower() != 'scratch' and '@sha256:' not in image and (':' not in image or image.endswith(':latest')):
                findings.append(finding('IAC002', 'Mutable container base image tag', f'{asset}:{line_no}',
                    'low', 'high', {'line': line_no, 'image': image},
                    'Pin base images to an explicit version tag or an immutable @sha256 digest.'))
        m_user = USER_RE.match(line)
        if m_user:
            last_user = m_user.group(1)
        m_env = ENV_SECRET_RE.match(line)
        if m_env:
            findings.append(finding('IAC004', 'Secret-named variable declared in Dockerfile ENV or ARG', f'{asset}:{line_no}',
                'medium', 'medium', {'line': line_no, 'variable': m_env.group(1)},
                'Do not bake secrets into image layers or build args; use runtime secret mounts (docker build --secret or orchestrator secrets).'))
    if last_user is None or last_user.lower() in ('root', '0', '0:0'):
        findings.append(finding('IAC001', 'Container image defaults to root user', asset, 'medium', 'high',
            {'final_user': last_user or 'unspecified (root)'},
            'Create and switch to a non-root USER before ENTRYPOINT or CMD.'))
    return findings


def check_compose(text, asset):
    findings = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        if re.search(r'^\s*privileged\s*:\s*true\b', raw, re.I):
            findings.append(finding('IAC003', 'Privileged container mode enabled', f'{asset}:{line_no}',
                'high', 'high', {'line': line_no, 'setting': 'privileged: true'},
                'Remove privileged: true and grant only minimal Linux capabilities via cap_add if required.'))
        if '/var/run/docker.sock' in raw and not raw.lstrip().startswith('#'):
            findings.append(finding('IAC003', 'Docker daemon socket mounted into container', f'{asset}:{line_no}',
                'high', 'high', {'line': line_no, 'mount': '/var/run/docker.sock'},
                'Mounting docker.sock grants root-equivalent host control. Avoid mounting it or use a restricted read-only socket proxy.'))
    return findings


def check_workflow(text, asset):
    findings = []
    has_permissions = False
    for line_no, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith('#'):
            continue
        if re.match(r'^\s*permissions\s*:', raw):
            has_permissions = True
        m_uses = USES_RE.match(raw)
        if m_uses:
            target = m_uses.group(1)
            if not target.startswith('./') and '@' in target:
                _, ref = target.rsplit('@', 1)
                if not re.fullmatch(r'[0-9a-f]{40}', ref):
                    findings.append(finding('CI002', 'GitHub Action not pinned to a full commit SHA', f'{asset}:{line_no}',
                        'low', 'high', {'line': line_no, 'uses': target},
                        'Pin third-party GitHub Actions to a 40-character commit SHA to prevent tag-mutation supply-chain attacks.'))
        if UNTRUSTED_EXPR.search(raw):
            findings.append(finding('CI003', 'Untrusted GitHub event context interpolated in workflow', f'{asset}:{line_no}',
                'high', 'medium', {'line': line_no},
                'Pass untrusted event fields through an environment variable instead of inline ${{ ... }} interpolation inside shell scripts.'))
    if not has_permissions:
        findings.append(finding('CI001', 'Workflow does not declare explicit GITHUB_TOKEN permissions', asset,
            'low', 'high', {'permissions_declared': False},
            'Add a top-level permissions: contents: read block and grant write scopes only to jobs that need them.'))
    return findings


def check_crypto(text, asset):
    findings = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith(('#', '//')):
            continue
        if WEAK_HASH_RE.search(raw):
            findings.append(finding('CRYP001', 'Weak cryptographic hash function (MD5/SHA-1) referenced', f'{asset}:{line_no}',
                'low', 'medium', {'line': line_no},
                'Use SHA-256/SHA-512 for integrity checks, or Argon2id/bcrypt/scrypt/PBKDF2 for password hashing.'))
        if NO_VERIFY_RE.search(raw):
            findings.append(finding('CRYP003', 'TLS certificate verification disabled in code', f'{asset}:{line_no}',
                'high', 'high', {'line': line_no},
                'Keep TLS verification enabled and configure a custom CA bundle when connecting to internal services.'))
    return findings


def audit_iac(path):
    root = Path(path).resolve(strict=True)
    report = assessment('iac', 'Infrastructure, CI/CD & crypto review', limitations=[
        'Static configuration review of Dockerfiles, Compose files, GitHub Actions workflows and source crypto calls.',
        'Does not inspect running containers, cluster RBAC or external secret managers.'])
    ignored = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'reports', 'work', 'dist', 'build'}
    paths = [root] if root.is_file() else []
    if root.is_dir():
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in ignored and not (Path(current) / d).is_symlink())
            for f in sorted(files):
                p = Path(current) / f
                if p.is_symlink():
                    continue
                lower = f.lower()
                in_workflows = '.github/workflows' in p.as_posix().lower()
                if (lower.startswith('dockerfile') or lower in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml')
                        or (in_workflows and lower.endswith(('.yml', '.yaml')))
                        or p.suffix.lower() in ('.py', '.js', '.ts')):
                    paths.append(p)
                if len(paths) > 500:
                    raise ValueError('IaC assessment is limited to 500 files')
    files_meta = []
    for p in paths:
        asset = p.name if root.is_file() else p.relative_to(root).as_posix()
        try:
            raw = read_limited(p, 1024 * 1024)
            text = raw.decode('utf-8-sig')
            lower = p.name.lower()
            found = []
            if lower.startswith('dockerfile'):
                found.extend(check_dockerfile(text, asset))
            elif lower in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'):
                found.extend(check_compose(text, asset))
            elif '.github/workflows' in asset.lower() or lower.endswith(('.yml', '.yaml')):
                if 'jobs:' in text and 'on:' in text:
                    found.extend(check_workflow(text, asset))
                elif 'services:' in text:
                    found.extend(check_compose(text, asset))
            elif p.suffix.lower() in ('.py', '.js', '.ts'):
                found.extend(check_crypto(text, asset))
            report['findings'].extend(found)
            report['sources'].append({**source_info(p, raw), 'name': asset})
            files_meta.append({'name': asset, 'status': 'analyzed', 'findings': len(found)})
        except (UnicodeError, OSError) as exc:
            report['status'] = 'partial'
            files_meta.append({'name': asset, 'status': 'not analyzed', 'reason': type(exc).__name__})
    report['data']['files'] = files_meta
    return report
