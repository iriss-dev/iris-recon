"""Dependency manifest review, CycloneDX SBOM generation and OSV advisory lookup."""
import json
import os
from pathlib import Path
import re
import tomllib
import urllib.request

from .model import assessment, finding, read_limited, source_info

REQ_LINE = re.compile(r'^\s*([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*([<>=!~]=?\s*[^\s;#]+)?')


def parse_requirements(text, source_name):
    deps = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.split('#', 1)[0].strip()
        if not line or line.startswith('-'):
            continue
        m = REQ_LINE.match(line)
        if m:
            name, spec = m.group(1), (m.group(2) or '').strip()
            pinned = spec.startswith('==') and '*' not in spec
            version = spec[2:].strip() if pinned else spec or 'unpinned'
            deps.append({'ecosystem': 'PyPI', 'name': name, 'version': version, 'pinned': pinned, 'file': source_name, 'line': line_no})
    return deps


def parse_pyproject(text, source_name):
    data = tomllib.loads(text)
    raw_deps = data.get('project', {}).get('dependencies', [])
    deps = []
    for item in raw_deps:
        m = REQ_LINE.match(item)
        if m:
            name, spec = m.group(1), (m.group(2) or '').strip()
            pinned = spec.startswith('==') and '*' not in spec
            version = spec[2:].strip() if pinned else spec or 'unpinned'
            deps.append({'ecosystem': 'PyPI', 'name': name, 'version': version, 'pinned': pinned, 'file': source_name, 'line': None})
    return deps


def parse_package_json(text, source_name):
    data = json.loads(text)
    deps = []
    for section in ('dependencies', 'devDependencies'):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            pinned = bool(re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', spec))
            deps.append({'ecosystem': 'npm', 'name': name, 'version': spec, 'pinned': pinned, 'file': source_name, 'line': None})
    return deps


def parse_cargo_lock(text, source_name):
    data = tomllib.loads(text)
    deps = []
    for pkg in data.get('package', []):
        name = pkg.get('name')
        version = pkg.get('version')
        if name and version:
            deps.append({'ecosystem': 'crates.io', 'name': name, 'version': version, 'pinned': True, 'file': source_name, 'line': None})
    return deps


def query_osv_batch(deps, timeout=8.0):
    pinned = [d for d in deps if d['pinned']]
    if not pinned:
        return {}
    queries = [{'package': {'name': d['name'], 'ecosystem': d['ecosystem']}, 'version': d['version']} for d in pinned[:100]]
    req = urllib.request.Request(
        'https://api.osv.dev/v1/querybatch',
        data=json.dumps({'queries': queries}).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'User-Agent': 'INMAP/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read(4 * 1024 * 1024).decode('utf-8'))
    except Exception:
        return {}
    results = {}
    for dep, res in zip(pinned[:100], payload.get('results', [])):
        vulns = res.get('vulns') or []
        if vulns:
            results[(dep['ecosystem'], dep['name'], dep['version'])] = [v.get('id') for v in vulns if v.get('id')]
    return results


def build_sbom(deps):
    components = []
    seen = set()
    for d in deps:
        key = (d['ecosystem'], d['name'], d['version'])
        if key in seen:
            continue
        seen.add(key)
        purl_type = {'PyPI': 'pypi', 'npm': 'npm', 'crates.io': 'cargo'}.get(d['ecosystem'], 'generic')
        components.append({
            'type': 'library',
            'name': d['name'],
            'version': d['version'],
            'purl': f'pkg:{purl_type}/{d["name"]}@{d["version"]}',
        })
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1, 'components': components}


def audit_dependencies(path, check_osv=False):
    root = Path(path).resolve(strict=True)
    report = assessment('dependencies', 'Dependency & SBOM review', limitations=[
        'Parses requirements.txt, pyproject.toml, package.json and Cargo.lock manifests.',
        'Unpinned ranges in library pyproject.toml files are normal; application deployments should pin transitive versions in lockfiles.'])
    manifest_names = {'requirements.txt', 'pyproject.toml', 'package.json', 'cargo.lock'}
    ignored = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'reports', 'work', 'dist', 'build'}
    paths = [root] if root.is_file() else []
    if root.is_dir():
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in ignored and not (Path(current) / d).is_symlink())
            for f in sorted(files):
                if f.lower() in manifest_names and not (Path(current) / f).is_symlink():
                    paths.append(Path(current) / f)
    if not paths:
        raise ValueError('No supported dependency manifests found (requirements.txt, pyproject.toml, package.json, Cargo.lock)')
    all_deps = []
    for p in paths:
        asset = p.name if root.is_file() else p.relative_to(root).as_posix()
        raw = read_limited(p, 2 * 1024 * 1024)
        text = raw.decode('utf-8-sig')
        lower = p.name.lower()
        if lower == 'requirements.txt':
            deps = parse_requirements(text, asset)
        elif lower == 'pyproject.toml':
            deps = parse_pyproject(text, asset)
        elif lower == 'package.json':
            deps = parse_package_json(text, asset)
        elif lower == 'cargo.lock':
            deps = parse_cargo_lock(text, asset)
        else:
            deps = []
        all_deps.extend(deps)
        report['sources'].append({**source_info(p, raw), 'name': asset})
        for d in deps:
            if not d['pinned'] and lower in ('requirements.txt', 'package.json'):
                loc = f'{asset}:{d["line"]}' if d['line'] else f'{asset}:{d["name"]}'
                report['findings'].append(finding('DEP002', 'Unpinned dependency version specification', loc,
                    'low', 'high', {'package': d['name'], 'spec': d['version'], 'ecosystem': d['ecosystem']},
                    'Pin exact versions or commit a lockfile with cryptographic hashes for reproducible builds.'))
    if check_osv and all_deps:
        advisories = query_osv_batch(all_deps)
        for d in all_deps:
            vulns = advisories.get((d['ecosystem'], d['name'], d['version']))
            if vulns:
                report['findings'].append(finding('DEP001', 'Dependency version matches public OSV advisories',
                    f'{d["file"]}:{d["name"]}@{d["version"]}', 'high', 'high',
                    {'package': d['name'], 'version': d['version'], 'ecosystem': d['ecosystem'], 'advisories': vulns},
                    'Upgrade the package to a patched release and review advisory applicability.'))
    report['data']['dependencies'] = all_deps
    report['data']['sbom'] = build_sbom(all_deps)
    return report
