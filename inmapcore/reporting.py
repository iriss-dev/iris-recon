"""Portable, offline reports with escaped evidence and integrity manifests for INMAP."""
import base64
import csv
import hashlib
import html
import json
from pathlib import Path

from .model import PRIORITIES

SCRIPT = """(() => {
const search = document.getElementById('search');
const priority = document.getElementById('priority');
function filter() {
  let shown = 0;
  document.querySelectorAll('.finding').forEach(card => {
    const match = card.textContent.toLowerCase().includes(search.value.toLowerCase()) &&
      (!priority.value || card.dataset.priority === priority.value);
    card.hidden = !match; if (match) shown++;
  });
  document.getElementById('visible-count').textContent = shown + ' findings shown';
}
if (search && priority) {
  search.addEventListener('input', filter);
  priority.addEventListener('change', filter);
}
const printBtn = document.getElementById('print');
if (printBtn) {
  printBtn.addEventListener('click', () => window.print());
}
})();"""

CSS = """
:root{color-scheme:dark;--bg:#090d14;--panel:#111722;--edge:#222d3d;--text:#e6edf5;--muted:#95a4b7;--accent:#00e5a3;--accent-dim:#00e5a322;--danger:#ff5c5c;--warning:#f5a623;--info:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}button,input,select{font:inherit}
header{border-bottom:1px solid var(--edge);background:#070a0f}.top{max-width:1240px;margin:auto;padding:18px 28px;display:flex;justify-content:space-between;align-items:center;gap:16px}
.brand{font-weight:800;letter-spacing:3px;font-size:16px;color:var(--text)}.brand span{color:var(--accent)}
nav{display:flex;gap:22px}nav a{text-decoration:none;color:var(--muted);font-size:13px;font-weight:500}nav a:hover{color:var(--accent)}
main{max-width:1240px;margin:auto;padding:36px 28px 64px}.eyebrow{font:12px ui-monospace,monospace;text-transform:uppercase;letter-spacing:2px;color:var(--accent)}
h1{font-size:clamp(28px,3.5vw,44px);line-height:1.15;letter-spacing:-1.2px;margin:12px 0 16px}h2{font-size:22px;letter-spacing:-.4px}h3{font-size:16px;margin:14px 0 8px}
.lede{color:var(--muted);max-width:820px}.hero{display:flex;justify-content:space-between;gap:20px;align-items:center}
.pill{border:1px solid var(--edge);border-radius:99px;padding:4px 12px;font-size:11px;font-weight:600;white-space:nowrap;text-transform:uppercase;letter-spacing:.6px}
.pill.completed{border-color:var(--accent);color:var(--accent);background:var(--accent-dim)}
.pill.tag{font-size:10px;padding:2px 8px;border-radius:4px;border:1px solid var(--edge);background:#161f2e;color:var(--muted)}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:28px 0}
.metric{background:var(--panel);border:1px solid var(--edge);border-radius:12px;padding:18px 20px}.metric strong{display:block;font-size:32px;line-height:1.2;color:var(--text)}.metric span{color:var(--muted);font-size:13px}
.section{margin-top:40px;scroll-margin-top:20px}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:18px 0}
input,select,button{background:var(--panel);border:1px solid var(--edge);color:var(--text);border-radius:8px;padding:9px 13px}input{flex:1;min-width:200px}button{cursor:pointer;background:#161f2e;font-weight:600}button:hover{border-color:var(--accent)}
.count{font-size:12px;color:var(--muted)}
.findings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.finding{border:1px solid var(--edge);border-left:3px solid var(--accent);border-radius:10px;background:var(--panel);padding:20px}
.finding[hidden]{display:none}.finding[data-priority=high]{border-left-color:var(--danger)}.finding[data-priority=medium]{border-left-color:var(--warning)}.finding[data-priority=low]{border-left-color:var(--info)}
.meta{display:flex;flex-wrap:wrap;gap:7px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.7px}
.asset{font:12px ui-monospace,monospace;overflow-wrap:anywhere;color:var(--muted);margin:8px 0}
.finding p{margin:10px 0}summary{cursor:pointer;color:var(--accent);font-size:13px;font-weight:500}
pre{background:#06090e;border:1px solid var(--edge);padding:14px;border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 ui-monospace,monospace;color:#c9d1d9}
code{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:11px 13px;border-bottom:1px solid var(--edge);vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);background:var(--panel)}.table-wrap{overflow:auto;border:1px solid var(--edge);border-radius:10px;margin-bottom:18px}
.notice{padding:16px 20px;background:var(--panel);border:1px solid var(--edge);border-radius:10px;color:var(--muted)}.notice ul{margin:8px 0 0;padding-left:18px}
.empty{padding:28px;border:1px dashed var(--edge);border-radius:10px;color:var(--muted);text-align:center}
footer{margin-top:48px;padding-top:20px;border-top:1px solid var(--edge);color:var(--muted);font-size:12px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px}
.rule{font:11px ui-monospace,monospace;color:var(--muted)}
@media(max-width:760px){.findings{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.hero{display:block}nav{display:none}main{padding:22px 14px}.top{padding:14px}.metric{padding:14px}h1{font-size:30px}}
@media print{:root{color-scheme:light;--bg:white;--panel:white;--edge:#ccc;--text:#111;--muted:#444;--accent:#00875a}body{font-size:11px}.toolbar,nav,#print{display:none}.findings{display:block}.finding{break-inside:avoid;margin-bottom:12px}pre{background:#f6f8fa}.finding[hidden]{display:block}.metrics{margin:15px 0}main{padding:10px}h1{font-size:26px}}
"""


def esc(value):
    return html.escape(str(value), quote=True)


def table(headers, rows):
    return '<div class="table-wrap"><table><thead><tr>' + ''.join(f'<th>{esc(x)}</th>' for x in headers) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join(f'<td>{x if str(x).startswith("<") and str(x).endswith(">") else esc(x)}</td>' for x in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def render_assessment(report):
    findings = sorted(report.get('findings', []), key=lambda f: (PRIORITIES.get(f['severity'], 9), f['asset'], f['rule']))
    data = report.get('data', {})
    cards = []
    for f in findings:
        reference = f.get('reference', '')
        link = f'<a href="{esc(reference)}" rel="noreferrer">Technical reference &#x2197;</a>' if reference.startswith('https://') else ''
        cards.append(
            f'<article class="finding" data-priority="{esc(f["severity"])}">'
            f'<div class="meta"><span class="pill">{esc(f["severity"])} priority</span>'
            f'<span class="pill">{esc(f["confidence"])} confidence</span>'
            f'<span class="pill">{esc(f["status"])}</span></div>'
            f'<h3>{esc(f["title"])}</h3><div class="asset">{esc(f["asset"])}</div>'
            f'<p>{esc(f["remediation"])}</p>'
            f'<details><summary>Evidence &amp; rationale</summary><pre>{esc(json.dumps(f["evidence"], indent=2, ensure_ascii=False))}</pre></details>'
            f'<p class="rule">{esc(f["rule"])} &middot; {esc(f["id"])}</p>{link}</article>'
        )

    inventory = ''

    # Hosts / Network services
    if 'hosts' in data:
        host_rows = []
        service_rows = []
        for h in data['hosts']:
            intel = h.get('intel', {})
            provider_tag = f'<span class="pill tag">{esc(intel.get("provider", "Unknown"))}</span>' if intel else ''
            open_ports_str = ', '.join(f'{p["port"]}/{p["protocol"]}' for p in h.get('ports', []) if p.get('state') == 'open') or 'None observed'
            host_rows.append((
                h['address'] + (' ' + provider_tag if provider_tag else ''),
                h.get('state', 'unknown'),
                ', '.join(h.get('hostnames', [])) or '&mdash;',
                open_ports_str
            ))
            for p in h.get('ports', []):
                svc = p.get('service', {})
                banner = svc.get('banner', '')
                banner_preview = f' ({banner[:60]}...)' if banner and len(banner) > 60 else (f' ({banner})' if banner else '')
                svc_desc = (' '.join(svc.get(k, '') for k in ('name', 'product', 'version')).strip() or 'Unknown') + banner_preview
                service_rows.append((
                    h['address'],
                    f"{p['port']}/{p.get('protocol', 'tcp')}",
                    p.get('state', 'unknown'),
                    svc_desc,
                    svc.get('method', 'lookup'),
                    svc.get('conf', 3)
                ))
        inventory += '<h3>Scanned Hosts</h3>' + table(['Address', 'Status', 'Names', 'Open ports'], host_rows)
        if service_rows:
            inventory += '<h3>Discovered Services</h3>' + table(['Host', 'Port', 'State', 'Service / Banner', 'Method', 'Confidence'], service_rows)

    # Subdomains / DNS Attack Surface
    if 'records' in data and report.get('kind') == 'subdomains':
        sub_rows = []
        for rec in data['records']:
            ips_str = ', '.join(rec.get('ips', [])) or '&mdash;'
            intel_tags = []
            for item in rec.get('intel', []):
                p = item.get('provider', '')
                if p and p not in intel_tags:
                    intel_tags.append(p)
            tag_html = ' '.join(f'<span class="pill tag">{esc(t)}</span>' for t in intel_tags) or '&mdash;'
            sub_rows.append((
                rec['subdomain'],
                'Active' if rec.get('resolved') else 'Unresolved',
                ips_str,
                tag_html
            ))
        inventory += '<h3>Discovered Subdomains &amp; DNS Records</h3>' + table(['Subdomain', 'DNS State', 'Resolved IPs', 'Infrastructure / ASN'], sub_rows)

    # Database tables
    if 'tables' in data:
        inventory += '<h3>Database Tables</h3>' + table(['Table', 'Columns', 'Primary key', 'Indexes', 'Foreign keys'], [
            (t['name'], len(t['columns']), ', '.join(c['name'] for c in t['columns'] if c['pk']) or 'None', len(t['indexes']), len(t['foreign_keys'])) for t in data['tables']])

    # Query plan
    if data.get('query_plan'):
        inventory += '<h3>Query Plan (Statement Not Executed)</h3>' + table(['ID', 'Parent', 'Detail'], [(x[0], x[1], x[3]) for x in data['query_plan']])

    # Source files
    if data.get('files'):
        inventory += '<h3>Source Files Inspected</h3>' + table(['File', 'Status', 'Findings'], [(x['name'], x['status'], x.get('findings', 0)) for x in data['files']])

    # Credentials
    if 'credentials' in data:
        inventory += '<h3>Credential Inventory</h3>' + table(
            ['File / key', 'Associated username', 'Password / secret', 'Compared with baseline'],
            [(f'{x["file"]} / {x["key"]}', x['username'] or 'Unknown', x['password_or_secret'], x['comparison']) for x in data['credentials']])
        if data.get('no_longer_observed'):
            inventory += '<h3>No longer observed (revocation not verified)</h3>' + table(
                ['File', 'Key', 'Username'], [(x['file'], x['key'], x['username'] or 'Unknown') for x in data['no_longer_observed']])

    # Web requests
    if 'requests' in data:
        inventory += '<h3>HTTP / TLS Observations</h3>' + table(['Request', 'Status', 'Bytes read', 'Truncated', 'Body SHA-256'], [(x['label'], x['status'], x['bytes'], x['truncated'], x['sha256']) for x in data['requests']])

    # Comparison / Baseline delta
    delta = report.get('comparison')
    comparison = ''
    if delta is not None:
        rows = [(x['address'], f'{x["port"]}/{x["protocol"]}', x['change'], x.get('interpretation', 'Review observation')) for x in delta.get('changes', [])]
        comparison = '<section class="section" id="changes"><h2>Changes Since Baseline</h2><p class="lede">' + esc(delta.get('warning', '')) + '</p>' + table(['Host', 'Port', 'Change', 'Interpretation'], rows)
        comparison += '<h3>Host changes</h3>' + table(['Host', 'Change'], [(x['address'], x['change']) for x in delta.get('host_changes', [])])
        comparison += '<details><summary>Comparison metadata</summary><pre>' + esc(json.dumps({k: v for k, v in delta.items() if k not in ('changes', 'host_changes')}, indent=2)) + '</pre></details></section>'

    # Summary metrics
    counts = [(sum(f['severity'] == level for f in findings), level.title() + ' priority') for level in ('high', 'medium', 'low')]
    counts.append((len(findings), 'Total review findings'))
    metrics = ''.join(f'<div class="metric"><strong>{n:02}</strong><span>{label}</span></div>' for n, label in counts)
    limitations = ''.join(f'<li>{esc(x)}</li>' for x in report.get('limitations', []))
    metadata = {k: v for k, v in report.items() if k not in ('findings', 'data', 'comparison')}
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>{esc(report['title'])} &middot; INMAP</title><style>{CSS}</style></head><body>
<header><div class="top"><div class="brand">IN<span> / </span>MAP</div><nav><a href="#findings">Findings</a><a href="#inventory">Evidence</a><a href="#provenance">Provenance</a></nav><button id="print" type="button">Print / PDF</button></div></header>
<main><div class="eyebrow">Assessment / {esc(report['kind'])}</div><div class="hero"><div><h1>{esc(report['title'])}</h1><p class="lede">Findings, supporting telemetry observations and prioritized remediation follow-up.</p></div><span class="pill completed">{esc(report['status'])}</span></div><div class="metrics">{metrics}</div>
<div class="notice"><strong>Assessment Coverage &amp; Methodology</strong><ul>{limitations}</ul></div>
<section class="section" id="findings"><h2>What Needs Attention</h2><div class="toolbar"><label for="search">Search</label><input id="search" type="search" placeholder="Asset, rule, evidence or recommendation..."><label for="priority">Priority</label><select id="priority"><option value="">All priorities</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><span class="count" id="visible-count">{len(findings)} findings shown</span></div><div class="findings">{''.join(cards)}</div>{'<p class="empty">No review findings from the checks performed. This does not establish that the asset is impenetrable.</p>' if not cards else ''}</section>
<section class="section" id="inventory"><h2>Evidence Inventory</h2>{inventory}<details><summary>Full structured telemetry observations</summary><pre>{esc(json.dumps(data, indent=2, ensure_ascii=False))}</pre></details></section>{comparison}
<section class="section" id="provenance"><h2>Provenance &amp; Cryptographic Integrity</h2><pre>{esc(json.dumps(metadata, indent=2, ensure_ascii=False))}</pre><p class="lede">The accompanying manifest contains SHA-256 hashes for all generated assessment artifacts. These confirm deterministic output integrity when checked against a trusted baseline.</p></section><footer><div>INMAP 1.0.0 &middot; Infrastructure &amp; Network Assessment Platform &middot; Self-Contained Offline Report</div><div>Cryptographic SHA-256 Manifest Included</div></footer></main><script>{SCRIPT}</script></body></html>'''


def csv_cell(value):
    value = str(value)
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else value


def save_assessment(report, out):
    folder = Path(out)
    folder.mkdir(parents=True, exist_ok=True)
    artifacts = {
        'report.json': json.dumps(report, indent=2, ensure_ascii=False),
        'report.html': render_assessment(report),
        'changes.json': json.dumps(report.get('comparison'), indent=2),
    }
    lines = [f'# {report["title"]}', '', f'Status: {report["status"]}', '', '## Coverage', '']
    lines += ['- ' + html.escape(x) for x in report.get('limitations', [])]
    for f in report.get('findings', []):
        lines += ['', f'## {html.escape(f["title"])}', '',
                  f'Priority: {f["severity"]}; confidence: {f["confidence"]}; status: {f["status"]}', '',
                  'Asset: ' + html.escape(f['asset']), '', html.escape(f['remediation']), '',
                  'Evidence:', '', *['    ' + line for line in json.dumps(f['evidence'], indent=2).splitlines()]]
    artifacts['report.md'] = '\n'.join(lines) + '\n'
    for name, content in artifacts.items():
        (folder / name).write_text(content, encoding='utf-8')
    with (folder / 'findings.csv').open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.writer(stream)
        keys = ['id', 'rule', 'severity', 'confidence', 'status', 'asset', 'title', 'remediation']
        writer.writerow(keys)
        writer.writerows([csv_cell(f[k]) for k in keys] for f in report.get('findings', []))
    names = list(artifacts) + ['findings.csv']
    manifest = {'algorithm': 'SHA-256', 'files': {name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in names}}
    (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return report
