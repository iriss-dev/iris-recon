# Iris Recon

An Nmap companion for repeatable network assessments: preserve evidence, create readable HTML reports, export structured JSON, and compare observations between runs.

**Status: initial working version.** This project adds reporting and workflow features around Nmap. It does not claim to outperform Nmap's scanning engine or automatically confirm vulnerabilities.

## Requirements

- Python 3.11+; no third-party Python packages.
- Nmap installed separately and available on `PATH` for `scan`. Offline `report` does not require Nmap.

Nmap is a separate project with its own license. It is not bundled here. See [Nmap downloads](https://nmap.org/download.html) and its [license](https://nmap.org/npsl/).

## Quick start

Analyze the included **synthetic** example without network activity:

```console
python iris_recon.py report examples/baseline.xml --out demo
```

Open `demo/report.html` in your browser. The `demo/report.json` file retains host states, explicit port states, service attributes, CPE identifiers, script output attributes, summarized extra-port states, and source provenance.

Compare two XML files:

```console
python iris_recon.py report examples/current.xml --baseline examples/baseline.xml --out comparison
```

This also produces `changes.json`. Changes distinguish newly observed ports, ports no longer observed, and changed state/service/CPE evidence. Missing observations are **not** labeled closed. Compare the same targets and port coverage; discovery, host availability and filtering can change visibility. Coverage and command differences are flagged. Host-only changes and nested NSE tables are not compared in this version.

## Authorized scanning

For your own localhost lab:

```console
python iris_recon.py scan 127.0.0.1 --scope 127.0.0.1/32 --ports 22,80,443 --out lab-run-001
```

The target must be a literal IPv4/IPv6 address or CIDR inside your declared authorized scope. DNS names are not supported in this version. Each target range is limited to 4096 addresses. The declared scope is a user assertion, not proof of authorization.

The wrapper uses TCP connect scanning, light service detection, normal timing, disabled DNS lookup, a configurable maximum packet rate (default 100; range 1–1000), and a 120-second host timeout. Service detection actively sends protocol probes. `--skip-discovery` adds `-Pn` when host discovery is blocked. The entire process has a 30-minute timeout. Nmap may summarize uninteresting ports rather than enumerate each one.

The scan output directory must be new to preserve existing evidence. It contains `command.json`, `scan.xml`, `nmap.log`, `report.json`, and `report.html`. Reports with a baseline also include `changes.json`. Offline report mode overwrites generated reports in the selected directory. Preserve the original XML and treat its contents and resulting reports as assessment data.

There is no arbitrary Nmap option passthrough, exploitation, brute force, or automatic NSE execution. Imported XML may contain results from other Nmap configurations; these are retained as evidence rather than executed. Reports load no external resources, escape scan-derived HTML, and do not fetch CVEs or upload findings.

## Validation

```console
python -m unittest discover -s tests -v
```

Tests cover XML evidence extraction, HTML injection escaping, observation changes, coverage changes, malformed/entity-bearing XML, scope/port validation, offline output, and mocked Nmap process orchestration. A mocked process is not a real Nmap integration test.

## Next milestones

- Real Nmap integration matrix on Windows, Linux and macOS.
- Host-level changes and explicit scan-coverage reconciliation.
- Opt-in TLS/HTTP assessment modules with evidence and remediation templates.
- Saved assessment scopes and signed evidence manifests.

## References

The parser uses Nmap's [recommended XML interface](https://nmap.org/book/output-formats-xml-output.html). The scan preset uses [light service detection](https://nmap.org/book/man-version-detection.html). A service fingerprint or open port is an observation, not a confirmed vulnerability or CVE match.
