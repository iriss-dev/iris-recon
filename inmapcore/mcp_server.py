"""Model Context Protocol (MCP) Stdio JSON-RPC 2.0 Server for INMAP."""
import json
import sys
import traceback
from typing import Dict, Any, List

from .fastscan import run_fast_scan
from .subdomains import audit_subdomains
from .intel import classify_ip
from .web_audit import audit_web, check_sqli
from .sql_audit import audit_source, audit_query, audit_sqlite
from .credentials import audit_credentials

TOOLS_METADATA = [
    {
        "name": "inmap_fast_scan",
        "description": "Perform native asynchronous TCP port scan on target IP/CIDR with service and banner detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IPv4/IPv6 address or CIDR range (e.g. 192.168.1.1 or 10.0.0.0/24)"},
                "scope": {"type": "string", "description": "Authorized IP scope CIDR"},
                "ports": {"type": "string", "description": "Port specification (e.g. '22,80,443' or '1-1024')", "default": "22,80,443,445,3389,8080,8443"},
                "max_rate": {"type": "integer", "description": "Maximum concurrent sockets", "default": 100}
            },
            "required": ["target", "scope"]
        }
    },
    {
        "name": "inmap_subdomain_recon",
        "description": "Perform passive Certificate Transparency (crt.sh) subdomain enumeration and DNS mapping for attack surface discovery.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Apex root domain to enumerate (e.g. example.com)"},
                "resolve_dns": {"type": "boolean", "description": "Whether to resolve discovered subdomains to IP addresses", "default": True}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "inmap_ip_intel",
        "description": "Classify an IP address against known ASN, Cloud Providers (AWS, Cloudflare, GCP, Azure, Hetzner) and internal network ranges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IPv4 or IPv6 address to classify"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "inmap_audit_web",
        "description": "Audit web HTTP headers, cookie security flags (Secure, HttpOnly, SameSite) and negotiated TLS parameters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target web URL (e.g. https://example.com/login)"},
                "scope": {"type": "string", "description": "Authorized target URL origin (e.g. https://example.com)"}
            },
            "required": ["url", "scope"]
        }
    },
    {
        "name": "inmap_audit_sql",
        "description": "Static code security audit of Python, JavaScript/TypeScript or SQL queries for SQL injection and unsafe queries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file or directory to audit"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "inmap_audit_credentials",
        "description": "Audit local source or config files for plaintext secrets, API keys, and credential rotation drift.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file or directory to inspect"}
            },
            "required": ["path"]
        }
    }
]


def handle_call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Execute requested tool and return standardized MCP content block."""
    if name == "inmap_fast_scan":
        target = args.get("target")
        scope = args.get("scope")
        ports = args.get("ports", "22,80,443,445,3389,8080,8443")
        max_rate = int(args.get("max_rate", 100))
        return run_fast_scan(target, scope, ports, max_rate=max_rate)

    elif name == "inmap_subdomain_recon":
        domain = args.get("domain")
        resolve = bool(args.get("resolve_dns", True))
        return audit_subdomains(domain, resolve_dns=resolve)

    elif name == "inmap_ip_intel":
        ip = args.get("ip")
        return classify_ip(ip)

    elif name == "inmap_audit_web":
        url = args.get("url")
        scope = args.get("scope")
        return audit_web(url, scope)

    elif name == "inmap_audit_sql":
        path = args.get("path")
        return audit_source(path)

    elif name == "inmap_audit_credentials":
        path = args.get("path")
        return audit_credentials(path, key_file='work/.inmap-key', reveal_secrets=False)

    else:
        raise ValueError(f"Unknown tool name: {name}")


def run_mcp_server():
    """Main JSON-RPC stdio loop for Model Context Protocol."""
    sys.stderr.write("INMAP Model Context Protocol (MCP) Server 1.0.0 listening on stdio...\n")
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"}
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "inmap-mcp-server",
                        "version": "1.0.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }
            }
        elif method == "notifications/initialized":
            # Notification, no response required
            continue
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": TOOLS_METADATA
                }
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                result_data = handle_call_tool(tool_name, tool_args)
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(result_data, indent=2, ensure_ascii=False)
                            }
                        ]
                    }
                }
            except Exception as exc:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [
                            {
                                "type": "text",
                                "text": f"Error executing {tool_name}: {exc}\n{traceback.format_exc()}"
                            }
                        ]
                    }
                }
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found"
                }
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
