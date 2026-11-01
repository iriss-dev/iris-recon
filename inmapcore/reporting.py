"""Portable, offline reports with escaped evidence and integrity manifests."""
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
search.addEventListener('input', filter); priority.addEventListener('change', filter);
document.getElementById('print').addEventListener('click', () => window.print());
})();"""

CSS = """
:root{color-scheme:dark;--bg:#090d14;--panel:#111722;--edge:#222d3d;--text:#e6edf5;--muted:#95a4b7;--accent:#00e5a3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}
a{color:var(--accent)}button,input,select{font:inherit}header{border-bottom:1px solid var(--edge)}.top{max-width:1240px;margin:auto;padding:20px 28px;display:flex;justify-content:space-between;align-items:center;gap:16px}.brand{font-weight:750;letter-spacing:3px}.brand span{color:var(--accent)}nav{display:flex;gap:22px}nav a{text-decoration:none;color:var(--muted);font-size:13px}
main{max-width:1240px;margin:auto;padding:38px 28px 64px}.eyebrow{font:12px ui-monospace,monospace;text-transform:uppercase;letter-spacing:2px;color:var(--accent)}h1{font-size:clamp(30px,4vw,48px);line-height:1.13;letter-spacing:-1.4px;margin:14px 0 18px}h2{font-size:23px;letter-spacing:-.5px}h3{font-size:17px;margin:10px 0}.lede{color:var(--muted);max-width:800px}.hero{display:flex;justify-content:space-between;gap:20px;align-items:center}.pill{border:1px solid var(--edge);border-radius:99px;padding:5px 12px;font-size:12px;white-space:nowrap}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:30px 0}.metric{background:var(--panel);border:1px solid var(--edge);border-radius:12px;padding:19px 22px}.metric strong{display:block;font-size:30px;line-height:1.3}.metric span{color:var(--muted);font-size:13px}.section{margin-top:38px;scroll-margin-top:20px}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:18px 0}input,select,button{background:var(--panel);border:1px solid var(--edge);color:var(--text);border-radius:8px;padding:10px 14px}input{flex:1;min-width:200px}button{cursor:pointer}.count{font-size:12px;color:var(--muted)}.findings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.finding{border:1px solid var(--edge);border-left:3px solid var(--accent);border-radius:10px;background:var(--panel);padding:22px}.finding[hidden]{display:none}.finding[data-priority=high]{border-left-color:#ff9393}.finding[data-priority=medium]{border-left-color:#f3c781}.finding[data-priority=low]{border-left-color:#8faeff}.meta{display:flex;flex-wrap:wrap;gap:7px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.7px}.asset{font:12px ui-monospace,monospace;overflow-wrap:anywhere;color:var(--muted)}.finding p{margin:10px 0}summary{cursor:pointer;color:var(--accent);font-size:13px}pre{background:#0b111b;border:1px solid var(--edge);padding:14px;border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 ui-monospace,monospace}code{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:12px 14px;border-bottom:1px solid var(--edge);vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted);background:var(--panel)}.table-wrap{overflow:auto;border:1px solid var(--edge);border-radius:10px}.notice{padding:16px 20px;background:var(--panel);border:1px solid var(--edge);border-radius:10px;color:var(--muted)}.notice ul{margin:0;padding-left:18px}.empty{padding:28px;border:1px dashed var(--edge);border-radius:10px;color:var(--muted)}footer{margin-top:40px;padding-top:20px;border-top:1px solid var(--edge);color:var(--muted);font-size:12px}.rule{font:11px ui-monospace,monospace;color:var(--muted)}
@media(max-width:760px){.findings{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.hero{display:block}nav{display:none}main{padding:26px 16px}.top{padding:16px}.metric{padding:16px}h1{font-size:34px}}
@media print{:root{color-scheme:light;--bg:white;--panel:white;--edge:#bbb;--text:#111;--muted:#444;--accent:#17664c}body{font-size:11px}.toolbar,nav,#print{display:none}.findings{display:block}.finding{break-inside:avoid;margin-bottom:12px}pre{background:#f8f8f8}.finding[hidden]{display:block}.metrics{margin:15px 0}main{padding:10px}h1{font-size:30px}}
"""


def esc(value):
    return html.escape(str(value), quote=True)


def table(headers, rows):
    return '<div class="table-wrap"><table><thead><tr>' + ''.join(f'<th>{esc(x)}</th>' for x in headers) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join(f'<td>{esc(x)}</td>' for x in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def render_assessment(report):
    findings = sorted(report.get('findings', []), key=lambda f: (PRIORITIES[f['severity']], f['asset'], f['rule']))
    data = report.get('data', {})
    cards = []
    for f in findings:
        reference = f.get('reference', '')
        link = f'<a href="{esc(reference)}" rel="noreferrer">Technical reference &#x2197;</a>' if reference.startswith('https://') else ''
        standards = ' &middot; '.join(esc(f[k]) for k in ('cwe', 'owasp') if f.get(k))
        rule_line = f'{esc(f["rule"])} &middot; {esc(f["id"])}' + (f' &middot; {standards}' if standards else '')
        cards.append(f'<article class="finding" data-priority="{esc(f["severity"])}"><div class="meta"><span class="pill">{esc(f["severity"])} priority</span><span class="pill">{esc(f["confidence"])} confidence</span><span class="pill">{esc(f["status"])}</span></div><h3>{esc(f["title"])}</h3><div class="asset">{esc(f["asset"])}</div><p>{esc(f["remediation"])}</p><details><summary>Evidence &amp; rationale</summary><pre>{esc(json.dumps(f["evidence"], indent=2, ensure_ascii=False))}</pre></details><p class="rule">{rule_line}</p>{link}</article>')
    inventory = ''
    if 'hosts' in data:
        rows = [(h['address'], h['state'], ', '.join(h.get('hostnames', [])) or '-',
                 ', '.join(f'{p["port"]}/{p["protocol"]}' for p in h['ports'] if p['state'] == 'open') or 'None explicitly observed') for h in data['hosts']]
        inventory += '<h3>Hosts</h3>' + table(['Address', 'Status', 'Names', 'Open ports'], rows)
        rows = [(h['address'], f'{p["port"]}/{p["protocol"]}', p['state'],
                 ' '.join(str(p['service'].get(k, '')) for k in ('name', 'product', 'version')).strip() or 'Unknown',
                 p['service'].get('method', 'unknown'), p['service'].get('conf', 'unknown')) for h in data['hosts'] for p in h['ports']]
        inventory += '<h3>Services</h3>' + table(['Host', 'Port', 'State', 'Service evidence', 'Method', 'Confidence / 10'], rows)
    if 'records' in data and report.get('kind') == 'subdomains':
        rows = [(r['subdomain'], 'resolved' if r.get('resolved') else 'unresolved',
                 ', '.join(r.get('ips', [])) or '-',
                 ', '.join({i.get('provider', '') for i in r.get('intel', []) if i.get('provider')}) or '-') for r in data['records']]
        inventory += '<h3>Subdomains</h3>' + table(['Subdomain', 'Status', 'Addresses', 'Provider'], rows)
    if report.get('kind') == 'dns':
        inventory += '<h3>Mail authentication records</h3>' + table(
            ['Mechanism', 'Records'],
            [('SPF', ', '.join(data.get('spf', [])) or 'None'), ('DMARC', ', '.join(data.get('dmarc', [])) or 'None')])
    if 'dependencies' in data:
        rows = [(d['ecosystem'], d['name'], d['version'], 'yes' if d['pinned'] else 'no', d['file']) for d in data['dependencies']]
        inventory += '<h3>Dependencies</h3>' + table(['Ecosystem', 'Package', 'Version', 'Pinned', 'Manifest'], rows)
    if 'tables' in data:
        inventory += table(['Table', 'Columns', 'Primary key', 'Indexes', 'Foreign keys'], [
            (t['name'], len(t['columns']), ', '.join(c['name'] for c in t['columns'] if c['pk']) or 'None', len(t['indexes']), len(t['foreign_keys'])) for t in data['tables']])
    if data.get('query_plan'):
        inventory += '<h3>Query plan (statement not executed)</h3>' + table(['ID', 'Parent', 'Detail'], [(x[0], x[1], x[3]) for x in data['query_plan']])
    if data.get('files'):
        inventory += table(['File', 'Status', 'Findings'], [(x['name'], x['status'], x.get('findings', 0)) for x in data['files']])
    if 'credentials' in data:
        inventory += '<h3>Credential inventory</h3>' + table(
            ['File / key', 'Associated username', 'Password / secret', 'Compared with baseline'],
            [(f'{x["file"]} / {x["key"]}', x['username'] or 'Unknown', x['password_or_secret'], x['comparison']) for x in data['credentials']])
        if data.get('no_longer_observed'):
            inventory += '<h3>No longer observed (revocation not verified)</h3>' + table(
                ['File', 'Key', 'Username'], [(x['file'], x['key'], x['username'] or 'Unknown') for x in data['no_longer_observed']])
    if 'requests' in data:
        inventory += table(['Request', 'Status', 'Bytes read', 'Truncated', 'Body SHA-256'], [(x['label'], x['status'], x['bytes'], x['truncated'], x['sha256']) for x in data['requests']])
    delta = report.get('comparison')
    comparison = ''
    if delta is not None:
        rows = [(x['address'], f'{x["port"]}/{x["protocol"]}', x['change'], x.get('interpretation', 'Review observation')) for x in delta['changes']]
        comparison = '<section class="section" id="changes"><h2>Changes since baseline</h2><p class="lede">' + esc(delta['warning']) + '</p>' + table(['Host', 'Port', 'Change', 'Interpretation'], rows)
        comparison += '<h3>Host changes</h3>' + table(['Host', 'Change'], [(x['address'], x['change']) for x in delta.get('host_changes', [])])
        comparison += '<details><summary>Comparison metadata</summary><pre>' + esc(json.dumps({k: v for k, v in delta.items() if k not in ('changes', 'host_changes')}, indent=2)) + '</pre></details></section>'
    counts = [(sum(f['severity'] == level for f in findings), level.title() + ' priority') for level in ('high', 'medium', 'low')]
    counts.append((len(findings), 'Total review findings'))
    metrics = ''.join(f'<div class="metric"><strong>{n:02}</strong><span>{label}</span></div>' for n, label in counts)
    limitations = ''.join(f'<li>{esc(x)}</li>' for x in report.get('limitations', []))
    metadata = {k: v for k, v in report.items() if k not in ('findings', 'data', 'comparison')}
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>{esc(report['title'])} &middot; INMAP</title><style>{CSS}</style></head><body>
<header><div class="top"><div class="brand">IN<span> / </span>MAP</div><nav><a href="#findings">Findings</a><a href="#inventory">Evidence</a><a href="#provenance">Provenance</a></nav><button id="print" type="button">Print / PDF</button></div></header>
<main><div class="eyebrow">Assessment / {esc(report['kind'])}</div><div class="hero"><div><h1>{esc(report['title'])}</h1><p class="lede">Findings, supporting observations and recommended follow-up from this assessment.</p></div><span class="pill">{esc(report['status'])}</span></div><div class="metrics">{metrics}</div>
<div class="notice"><strong>Assessment coverage</strong><ul>{limitations}</ul></div>
<section class="section" id="findings"><h2>What needs attention</h2><div class="toolbar"><label for="search">Search</label><input id="search" type="search" placeholder="Asset, rule, evidence or recommendation..."><label for="priority">Priority</label><select id="priority"><option value="">All priorities</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><span class="count" id="visible-count">{len(findings)} findings shown</span></div><div class="findings">{''.join(cards)}</div>{'<p class="empty">No findings from the checks performed. This does not establish that the asset is secure.</p>' if not cards else ''}</section>
<section class="section" id="inventory"><h2>Evidence inventory</h2>{inventory}<details><summary>Full structured observations</summary><pre>{esc(json.dumps(data, indent=2, ensure_ascii=False))}</pre></details></section>{comparison}
<section class="section" id="provenance"><h2>Provenance &amp; coverage</h2><pre>{esc(json.dumps(metadata, indent=2, ensure_ascii=False))}</pre><p class="lede">The accompanying manifest contains SHA-256 hashes for generated artifacts. These detect changes when compared with a trusted copy; they are not a digital signature.</p></section><footer>INMAP 1.0 &middot; Local report &middot; No external scripts, fonts or analytics &middot; Review priorities are not CVSS scores</footer></main><script>{SCRIPT}</script></body></html>'''


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
    if 'sbom' in report.get('data', {}):
        artifacts['sbom.cdx.json'] = json.dumps(report['data']['sbom'], indent=2, ensure_ascii=False)
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
