"""Model Context Protocol (MCP) JSON-RPC 2.0 stdio server."""
import json
import sys
import traceback

from .credentials import audit_credentials
from .deps_audit import audit_dependencies
from .dns_audit import audit_dns
from .fastscan import run_fast_scan
from .iac_audit import audit_iac
from .intel import classify_ip
from .sql_audit import audit_source
from .subdomains import audit_subdomains
from .web_audit import audit_web

TOOLS_METADATA = [
    {
        'name': 'inmap_fast_scan',
        'description': 'Run asynchronous TCP port scan and service banner check within an authorized IP scope.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'target': {'type': 'string'},
                'scope': {'type': 'string'},
                'ports': {'type': 'string', 'default': '22,80,443,445,3389,8080,8443'},
                'max_rate': {'type': 'integer', 'default': 100},
            },
            'required': ['target', 'scope'],
        },
    },
    {
        'name': 'inmap_subdomain_recon',
        'description': 'Query Certificate Transparency logs and resolve DNS records for a domain.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'domain': {'type': 'string'},
                'resolve_dns': {'type': 'boolean', 'default': True},
            },
            'required': ['domain'],
        },
    },
    {
        'name': 'inmap_ip_intel',
        'description': 'Classify IPv4/IPv6 address against cloud provider, CDN and RFC1918 ranges.',
        'inputSchema': {
            'type': 'object',
            'properties': {'ip': {'type': 'string'}},
            'required': ['ip'],
        },
    },
    {
        'name': 'inmap_audit_dns',
        'description': 'Check domain SPF and DMARC mail authentication policies.',
        'inputSchema': {
            'type': 'object',
            'properties': {'domain': {'type': 'string'}},
            'required': ['domain'],
        },
    },
    {
        'name': 'inmap_audit_web',
        'description': 'Check HTTP security headers, CORS, cookie flags, login CSRF/rate-limit hints and TLS.',
        'inputSchema': {
            'type': 'object',
            'properties': {'url': {'type': 'string'}, 'scope': {'type': 'string'}},
            'required': ['url', 'scope'],
        },
    },
    {
        'name': 'inmap_audit_sql',
        'description': 'Static analysis of Python, JS/TS and SQL files for dynamic SQL construction.',
        'inputSchema': {
            'type': 'object',
            'properties': {'path': {'type': 'string'}},
            'required': ['path'],
        },
    },
    {
        'name': 'inmap_audit_credentials',
        'description': 'Scan local files for credential literals and high-entropy token signatures.',
        'inputSchema': {
            'type': 'object',
            'properties': {'path': {'type': 'string'}},
            'required': ['path'],
        },
    },
    {
        'name': 'inmap_audit_iac',
        'description': 'Review Dockerfiles, Compose files, GitHub Actions workflows and crypto calls.',
        'inputSchema': {
            'type': 'object',
            'properties': {'path': {'type': 'string'}},
            'required': ['path'],
        },
    },
    {
        'name': 'inmap_audit_deps',
        'description': 'Inspect dependency manifests, build CycloneDX SBOM and check version pinning.',
        'inputSchema': {
            'type': 'object',
            'properties': {
                'path': {'type': 'string'},
                'check_osv': {'type': 'boolean', 'default': False},
            },
            'required': ['path'],
        },
    },
]


def handle_call_tool(name, args):
    if name == 'inmap_fast_scan':
        return run_fast_scan(
            args['target'],
            args['scope'],
            args.get('ports', '22,80,443,445,3389,8080,8443'),
            max_rate=int(args.get('max_rate', 100)),
        )
    if name == 'inmap_subdomain_recon':
        return audit_subdomains(args['domain'], resolve_dns=bool(args.get('resolve_dns', True)))
    if name == 'inmap_ip_intel':
        return classify_ip(args['ip'])
    if name == 'inmap_audit_dns':
        return audit_dns(args['domain'])
    if name == 'inmap_audit_web':
        return audit_web(args['url'], args['scope'])
    if name == 'inmap_audit_sql':
        return audit_source(args['path'])
    if name == 'inmap_audit_credentials':
        return audit_credentials(args['path'], key_file='work/.inmap-key', reveal=False)
    if name == 'inmap_audit_iac':
        return audit_iac(args['path'])
    if name == 'inmap_audit_deps':
        return audit_dependencies(args['path'], check_osv=bool(args.get('check_osv', False)))
    raise ValueError(f'Unknown tool: {name}')


def run_mcp_server():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as exc:
            sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': str(exc)}}) + '\n')
            sys.stdout.flush()
            continue

        req_id = req.get('id')
        method = req.get('method')
        params = req.get('params') or {}

        if method == 'initialize':
            resp = {
                'jsonrpc': '2.0',
                'id': req_id,
                'result': {
                    'protocolVersion': '2024-11-05',
                    'serverInfo': {'name': 'inmap', 'version': '1.0.0'},
                    'capabilities': {'tools': {}},
                },
            }
        elif method == 'notifications/initialized':
            continue
        elif method == 'tools/list':
            resp = {'jsonrpc': '2.0', 'id': req_id, 'result': {'tools': TOOLS_METADATA}}
        elif method == 'tools/call':
            try:
                data = handle_call_tool(params.get('name'), params.get('arguments') or {})
                resp = {
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'result': {'content': [{'type': 'text', 'text': json.dumps(data, indent=2, ensure_ascii=False)}]},
                }
            except Exception as exc:
                resp = {
                    'jsonrpc': '2.0',
                    'id': req_id,
                    'result': {'isError': True, 'content': [{'type': 'text', 'text': f'{exc}\n{traceback.format_exc()}'}]},
                }
        else:
            resp = {'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32601, 'message': f'Method not found: {method}'}}

        sys.stdout.write(json.dumps(resp) + '\n')
        sys.stdout.flush()
