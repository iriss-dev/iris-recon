# INMAP

[![Tests](https://github.com/iriss-dev/iris-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/iriss-dev/iris-recon/actions/workflows/ci.yml)

Network, web, SQL, DNS, IaC and dependency assessment tools with local evidence reports.

INMAP (formerly `iris-recon`) includes an asynchronous TCP scanner, Nmap XML comparison, Certificate Transparency subdomain discovery, SPF/DMARC checks, SQL static analysis, read-only SQLite inspection, HTTP/TLS/CORS checks, credential tracking, container/CI linting, CycloneDX SBOM generation and an MCP stdio server.

## Install

Requires Python 3.11+. A virtual environment is recommended.

```console
git clone https://github.com/iriss-dev/iris-recon.git
cd iris-recon
python -m pip install -e .
inmap doctor
```

Both `inmap` and `iris-recon` commands are installed. [Nmap](https://nmap.org/download.html) is optional: `scan --engine auto` uses Nmap when present on `PATH` and falls back to the built-in asynchronous TCP scanner otherwise.

## Commands

| Command | Purpose |
| --- | --- |
| `scan` | Scoped TCP port scans (`--engine auto\|native\|nmap`) and banner checks |
| `report` | Offline Nmap XML inventory and baseline comparison |
| `subdomains` | Certificate Transparency (`crt.sh`) lookup and DNS resolution |
| `dns` | Domain SPF and DMARC mail authentication review |
| `intel` | Offline IP classification against cloud, CDN and RFC1918 ranges |
| `web` | HTTP security headers, CORS, cookie flags, login form controls and TLS |
| `sqli-check` | Repeated SQL-error feedback from one GET parameter |
| `sql-code` | SQL construction in Python, direct-call hints in JS/TS, SQL files |
| `sql-query` | Unscoped writes, destructive statements and query lint |
| `sql-db` | Read-only SQLite schema, indexes, integrity and query plans |
| `credentials` | Local credential literals, token signatures, entropy and rotation tracking |
| `iac` | Dockerfile, Compose, GitHub Actions workflow and crypto call review |
| `deps` | Dependency manifest pinning, CycloneDX SBOM export and optional OSV lookup |
| `combine` | Merge several module `report.json` files into one assessment |
| `mcp` | Model Context Protocol (JSON-RPC 2.0 stdio) server |
| `doctor` | Runtime versions and engine availability |

Assessments generate `report.html`, `report.json`, `report.md`, `findings.csv` and `manifest.json` (plus `sbom.cdx.json` for `deps`). Findings include CWE and OWASP Top 10 mappings where applicable.

## Network, Subdomains and DNS

```console
inmap scan 127.0.0.1 --scope 127.0.0.1/32 --engine native --ports 22,80,443 --out reports/net
inmap report examples/current.xml --baseline examples/baseline.xml --out reports/xml
inmap subdomains example.com --out reports/subdomains
inmap dns example.com --out reports/dns
inmap intel 104.16.12.34
```

Targets for `scan` must reside within the declared `--scope`. Profiles are `common`, `web`, `database` and `full`.

## Web, SQL and Database

```console
inmap web "http://127.0.0.1:8000/" --scope "http://127.0.0.1:8000" --out reports/web
inmap sqli-check "http://127.0.0.1:8000/search?id=1" --scope "http://127.0.0.1:8000" --param id --out reports/sqli
inmap sql-code ./src --out reports/source
inmap sql-query examples/review.sql --out reports/queries
inmap sql-db ./lab.sqlite --query-file ./lookup.sql --out reports/db
```

`web` inspects security headers, CORS policies, cookie flags, negotiated TLS and defensive controls on password forms (CSRF token fields and rate-limit headers) without submitting credentials.

## Credentials, IaC and Dependencies

```console
inmap credentials ./config --key-file work/credentials.key --out reports/creds
inmap iac . --out reports/iac
inmap deps . --osv --out reports/deps
```

`credentials` masks secret values by default (`--reveal-secrets` includes full literals for private local review) and compares HMAC-SHA-256 fingerprints across runs. `iac` checks Dockerfiles, Compose configurations, GitHub workflows and weak hash/TLS settings in source files. `deps` inspects `requirements.txt`, `pyproject.toml`, `package.json` and `Cargo.lock`.

## Development

```console
python -m unittest discover -s tests -v
```
