# INMAP (Infrastructure & Network Mapper)

[![Tests](https://github.com/iriss-dev/iris-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/iriss-dev/iris-recon/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.0.0-00e5a3.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**INMAP** is a modular, high-performance security assessment and infrastructure intelligence platform. Built with a dual-engine architecture (Zero-dependency Native Async Python + Rust Core), INMAP delivers port scanning, threat intelligence, passive Certificate Transparency reconnaissance, static SQL analysis, web security auditing, credential tracking, and an AI-native Model Context Protocol (MCP) server.

Formerly known as `iris-recon`, INMAP retains 100% backward compatibility for existing pipelines, scripts, and imports.

---

## Key Highlights

- **Dual Scanning Engine**:
  - **Native Async TCP Engine**: Built-in non-blocking port scanner & banner grabber using Python standard library `asyncio` & `socket`. Runs anywhere with **zero external dependencies** (no Nmap installation required).
  - **Nmap XML Engine**: Full integration with Nmap XML output, state diffing, and baseline comparison.
  - **Smart Fallback (`--engine auto`)**: Automatically detects Nmap if present; falls back seamlessly to the native async engine if missing.
- **Attack Surface Reconnaissance (`subdomains`)**:
  - Passive Certificate Transparency (crt.sh) log analysis.
  - Async non-blocking DNS resolution (A / AAAA) and sensitive subdomain detection (`dev.*`, `admin.*`, `vpn.*`, `staging.*`).
- **ASN & Cloud Threat Intelligence (`intel`)**:
  - Fast offline CIDR matching classifying Cloudflare, AWS, Google Cloud, Microsoft Azure, DigitalOcean, Hetzner, OVH, and RFC1918 private scopes.
- **Model Context Protocol (MCP) Server (`mcp`)**:
  - Native Stdio JSON-RPC 2.0 server (`inmap mcp`) enabling LLM agents (Claude, ChatGPT, Antigravity) to execute security audits and assessments directly.
- **High-Performance Rust Core (`crates/inmap-core`)**:
  - Standalone Rust 2021 crate providing sub-millisecond CIDR radix lookups and socket connect scanning.
- **Tactical Onyx Reporting**:
  - Self-contained, zero-CDN, dark-mode HTML reports with CSP SHA-256 integrity, JSON, Markdown, CSV, and SHA-256 manifest verification.

---

## Installation

Requires Python 3.11+.

```console
git clone https://github.com/iriss-dev/iris-recon.git
cd iris-recon
python -m pip install -e .
inmap doctor
```

*Note: The CLI executable `inmap` and the legacy alias `iris-recon` are both registered.*

---

## Commands Overview

| Command | Engine / Scope | Purpose |
| --- | --- | --- |
| `scan` | Native / Nmap | Network port scanning, banner grabbing, and service risk review |
| `subdomains` | CT Logs + Async DNS | Passive Certificate Transparency subdomain discovery & attack surface mapping |
| `intel` | Offline Radix CIDR | ASN, Cloud provider (AWS, Cloudflare, GCP, Azure, DO), and threat tags |
| `report` | Offline | Nmap XML parsing, delta calculation, and baseline comparison |
| `web` | Active HTTP/TLS | HTTP security headers, cookie flags (Secure/HttpOnly/SameSite), TLS parameters |
| `sqli-check` | Active GET probe | Single-quote perturbation and repeated database error feedback analysis |
| `sql-code` | Static AST / Lexical | Python AST string construction & JS/TS lexical hints for dynamic SQL |
| `sql-query` | Static Linter | Lint queries for missing WHERE clauses, wildcards, and destructive statements |
| `sql-db` | Read-only SQLite | Schema inspection, FK index coverage, integrity check, EXPLAIN QUERY PLAN |
| `credentials` | Local Secret Audit | Local secret literals, masked reporting, and HMAC-SHA256 rotation drift |
| `combine` | Multi-module | Merge multiple assessment `report.json` files into a single unified report |
| `mcp` | Stdio JSON-RPC 2.0 | Start the native Model Context Protocol (MCP) server for AI coding agents |
| `doctor` | Diagnostics | Display runtime versions, installed engines, and system capabilities |

---

## Usage Examples

### 1. Network Port Scanning

```console
# Native async scan (No Nmap required!)
inmap scan 192.168.1.1 --scope 192.168.1.0/24 --engine native --ports 22,80,443,3306,8080 --out reports/scan-local

# Auto mode (Uses Nmap if available, falls back to native async)
inmap scan 10.0.0.1 --scope 10.0.0.0/16 --profile web --out reports/scan-web

# Dry run command verification
inmap scan 127.0.0.1 --scope 127.0.0.1/32 --dry-run
```

### 2. Attack Surface Reconnaissance (Subdomains)

```console
# Discover subdomains via CT logs and resolve active DNS records
inmap subdomains example.com --out reports/subdomains-example

# Discover subdomains passively without active DNS resolution
inmap subdomains example.com --no-resolve --out reports/subdomains-passive
```

### 3. IP Threat Intelligence

```console
inmap intel 104.16.12.34
```
Output:
```json
{
  "ip": "104.16.12.34",
  "version": 4,
  "is_private": false,
  "provider": "Cloudflare",
  "category": "cdn",
  "asn_org": "Cloudflare, Inc.",
  "risk_tags": ["cdn-edge-proxy"]
}
```

### 4. Model Context Protocol (MCP) Server for AI Agents

Connect INMAP directly to your AI development environment by adding it to your MCP configuration:

```json
{
  "mcpServers": {
    "inmap": {
      "command": "python",
      "args": ["-m", "inmapcore.mcp_server"]
    }
  }
}
```
Exposed tools: `inmap_fast_scan`, `inmap_subdomain_recon`, `inmap_ip_intel`, `inmap_audit_web`, `inmap_audit_sql`, `inmap_audit_credentials`.

### 5. Web, SQL & Credential Auditing

```console
# Security headers and TLS verification
inmap web "https://app.example.com" --scope "https://app.example.com" --out reports/web

# Python AST / JS source code audit
inmap sql-code ./src --out reports/sql-code

# Read-only SQLite database inspection
inmap sql-db ./app.sqlite --out reports/sqlite

# Credential rotation and literal leak tracking
inmap credentials ./config --key-file work/.key --out reports/creds
```

---

## Backward Compatibility

All legacy `iris_recon.py` scripts and `iriscore` module imports remain fully functional:

```python
# Legacy imports continue to work without modification:
from iriscore.model import assessment, finding
from iriscore.reporting import save_assessment
from iriscore.sql_audit import audit_source

# Or use the new INMAP namespace:
from inmapcore.fastscan import run_fast_scan
from inmapcore.intel import classify_ip
from inmapcore.subdomains import audit_subdomains
```

---

## Running Tests

Run the complete 37-test automated verification suite:

```console
python -m unittest discover -s tests -v
```

---

## License

Licensed under the Apache License, Version 2.0.
