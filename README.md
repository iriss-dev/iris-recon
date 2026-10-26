# Iris Recon

[![Tests](https://github.com/iriss-dev/iris-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/iriss-dev/iris-recon/actions/workflows/ci.yml)

Network, web and SQL assessment tools. Run a check, inspect the evidence, and compare it with the next assessment.

Nmap handles network scanning. Iris Recon adds reports, SQL source review, read-only SQLite inspection, HTTP checks and local credential tracking.

## Install

Requires Python 3.11+. A virtual environment is recommended.

```console
git clone https://github.com/iriss-dev/iris-recon.git
cd iris-recon
python -m pip install -e .
python iris_recon.py doctor
```

The package also installs an `iris-recon` command. [Nmap](https://nmap.org/download.html) is required only for `scan`, is installed separately, and has its [own license](https://nmap.org/npsl/).

## Commands

| Command | Purpose |
| --- | --- |
| `scan` | Scoped Nmap TCP scans and service detection |
| `report` | Nmap XML inventory and comparison with a baseline |
| `web` | HTTP headers, cookie flags and negotiated TLS |
| `sql-code` | SQL construction in Python, direct-call hints in JS/TS, SQL files |
| `sql-query` | Unscoped writes, destructive statements and query review |
| `sql-db` | SQLite schema, indexes, integrity and query plans |
| `sqli-check` | Repeated SQL-error feedback from one GET parameter |
| `credentials` | Local credential literals and comparisons between runs |
| `combine` | Several module reports in one assessment |
| `doctor` | Runtime versions and Nmap availability |

Assessments produce HTML, JSON, Markdown, CSV and a SHA-256 manifest. HTML works offline, supports search and priority filters, and can be printed to PDF from the browser. Findings include evidence, confidence and suggested follow-up. Review priorities are not CVSS scores.

## Network

```console
python iris_recon.py report examples/current.xml --baseline examples/baseline.xml --out reports/network
python iris_recon.py scan 127.0.0.1 --scope 127.0.0.1/32 --ports 22,80,443 --skip-discovery --out reports/lab-001
```

The example XML is a fixture; importing it makes no network requests. Scan profiles are `common`, `web`, `database` and `full`; explicit `--ports` override a profile. `--dry-run` prints the command. `--nmap-path` selects an executable.

Targets are literal IPv4/IPv6 addresses or CIDRs inside the declared scope, up to 4096 addresses per run. Defaults: TCP connect, light version detection, normal timing, maximum packet rate 100, 120-second host timeout and 30-minute process timeout. `--max-rate` accepts 1-1000. Scan output directories must be new.

Comparisons include host changes and declared port coverage. A missing port entry does not prove closure: discovery, summarized results and incomplete scans can explain it. Service fingerprints are not confirmed vulnerabilities or CVE matches.

## SQL source and query review

```console
python iris_recon.py sql-code ./src --out reports/source
python iris_recon.py sql-query examples/review.sql --out reports/queries
```

Python analysis follows local assignments into common SQL execution methods and identifies interpolation, concatenation and formatting. Literal queries with separately bound values are not flagged as dynamic construction. Unresolved query origins require manual review. Complex control flow, wrappers and indirect calls can be missed; this is not interprocedural taint analysis.

JS/TS checks are lexical hints for dynamic text directly inside query calls. Comments and non-SQL APIs can match; query variables and wrappers can be missed. Source is never executed. Query review covers common SQL constructs rather than full dialect validation. Reports omit source snippets and query literals.

Use parameter binding, for example with Python's SQLite driver:

```python
cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
```

Use the placeholder style supported by your driver. Dynamic identifiers need an allow-list or an identifier-composition API; value placeholders do not bind table or column names.

## SQLite inspection

```console
python iris_recon.py sql-db ./lab.sqlite --out reports/database
python iris_recon.py sql-db ./lab.sqlite --query-file ./lookup.sql --out reports/query-plan
```

Supports **SQLite files**, opened read-only with `query_only` enabled. Checks schema, index prefixes for foreign keys, integrity and foreign-key violations. The optional file must contain one SELECT statement without unbound placeholders. It is prepared with EXPLAIN QUERY PLAN, not executed to retrieve rows. Prefer an offline snapshot; live SQLite access may require locking or existing WAL sidecars.

This module does not connect to PostgreSQL/MySQL servers or infer their users, permissions or application connection settings. Index and table-scan recommendations depend on workload.

## HTTP and SQL injection signals

```console
python iris_recon.py web "http://127.0.0.1:8000/" --scope "http://127.0.0.1:8000" --out reports/web
python iris_recon.py sqli-check "http://127.0.0.1:8000/search?id=1" --scope "http://127.0.0.1:8000" --param id --out reports/sqli
```

Use active checks on systems you own or are authorized to assess. The origin must match the declared scope. Redirects are not followed, TLS verification stays enabled and responses are bounded. TLS records one negotiated connection, not every supported protocol/cipher. Header recommendations depend on the endpoint's purpose.

`sqli-check` takes two baselines and repeats one quote perturbation twice. New, repeated database-error feedback becomes a **potential** finding. Existing errors, unstable baselines and some status changes make the result inconclusive. This does not prove exploitability or rule out blind injection. Choose a read-only route: GET requests can still have side effects.

There is no crawling, credential guessing, database dumping or account extraction. Bodies, cookie values and query values are omitted from reports. URL paths and selected security headers remain visible.

## Credentials and rotation checks

```console
python iris_recon.py credentials ./config --key-file work/credentials.key --out reports/credentials-before
python iris_recon.py credentials ./config --key-file work/credentials.key --baseline reports/credentials-before/report.json --out reports/credentials-after
```

The report shows associated usernames, locations and comparison results:

| Result | Meaning |
| --- | --- |
| `unchanged` | Same literal at the tracked configuration entry |
| `changed` | Different literal at that entry |
| `newly_observed` | Entry was not in the baseline |
| No longer observed | Previous entry is missing from current observations |

This checks **files**, not which password a server accepts. Changed values do not prove successful rotation; missing entries do not prove revocation. Username association is best-effort. Duplicate keys are matched by occurrence order. Inspecting a different scope or unreadable files affects comparisons.

Passwords and tokens are masked by default. Include full literal values in a **private local report** with `--reveal-secrets`:

```console
python iris_recon.py credentials ./config --key-file work/credentials.key --reveal-secrets --out reports/credentials-private
```

HMAC-SHA-256 comparisons use a locally generated random key. Reuse that key and keep it private; it is not included in reports. Reports containing revealed credentials must remain private. This module reads local literals, not credentials from remote services.

`reports/`, `work/`, environment files, database files and generated report filenames are ignored by Git. Exclusions do not protect files copied elsewhere or added with `git add -f`.

## Combined reports and CI

```console
python iris_recon.py combine reports/network/report.json reports/source/report.json --out reports/combined
python iris_recon.py sql-code ./src --out reports/source --fail-on medium
```

Exit codes: `0` completed, `1` input/operational error, `2` finding threshold reached, `3` partial/inconclusive. A selected finding threshold takes precedence over `3`.

Offline output files are replaced when a directory is reused; use separate directories to retain baselines. The manifest is an integrity record, not a signature. Compare it against a trusted copy.

## Development

```console
python -m unittest discover -s tests -v
```

Tests cover a local HTTP/SQLite lab, a parameterized-query control, credential rotation, XML entity rejection and report escaping. The Nmap integration test scans localhost and skips if Nmap is absent. CI installs Nmap on Linux; Windows exercises the remaining modules.

References: [Nmap XML](https://nmap.org/book/output-formats-xml-output.html), [OWASP SQL injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [SQLite PRAGMA](https://www.sqlite.org/pragma.html).
