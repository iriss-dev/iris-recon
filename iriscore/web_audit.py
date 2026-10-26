"""Bounded HTTP/TLS checks and differential SQL error probing."""
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
import re
import ssl
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .model import assessment, finding
from .sql_audit import OWASP_SQL, PARAMETERIZE

MAX_BODY = 512 * 1024
ERRORS = {
    'mysql': r'you have an error in your sql syntax',
    'postgresql': r'(?:syntax error at or near|psycopg\d?\.errors\.SyntaxError)',
    'sqlite': r'(?:sqlite3\.OperationalError|SQLite3?::SQLException|unrecognized token:)',
    'sqlserver': r'unclosed quotation mark after the character string',
    'oracle': r'ORA-(?:00933|01756|00936)\b',
}


def origin(url):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username is not None or parts.password is not None:
        raise ValueError('Use an HTTP(S) URL without embedded credentials')
    if parts.fragment or any(ord(c) < 32 for c in url):
        raise ValueError('URL fragments and control characters are not supported')
    return parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == 'https' else 80)


def validate_scope(url, scope):
    if origin(url) != origin(scope):
        raise ValueError('URL must match the authorized scope origin (scheme, host and port)')
    scope_parts = urlsplit(scope)
    if scope_parts.path not in ('', '/') or scope_parts.query:
        raise ValueError('Scope must be an origin, such as https://app.example:443')


def redacted_url(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode([(k, '[redacted]') for k, _ in parse_qsl(parts.query, keep_blank_values=True)]), ''))


def fetch(url, scope, label='baseline', timeout=10):
    validate_scope(url, scope)
    scheme, host, port = origin(url)
    parts = urlsplit(url)
    cls = http.client.HTTPSConnection if scheme == 'https' else http.client.HTTPConnection
    kwargs = {'context': ssl.create_default_context()} if scheme == 'https' else {}
    conn = cls(host, port, timeout=timeout, **kwargs)
    started = time.monotonic()
    try:
        conn.connect()
        tls = None
        if scheme == 'https':
            cert = conn.sock.getpeercert()
            tls = {'protocol': conn.sock.version(), 'cipher': conn.sock.cipher()[0],
                   'not_after': cert.get('notAfter'), 'hostname_and_chain_verified': True}
        conn.request('GET', urlunsplit(('', '', parts.path or '/', parts.query, '')),
                     headers={'User-Agent': 'Iris-Recon/0.2', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        request_socket = conn.sock
        response = conn.getresponse()
        chunks, size = [], 0
        # read1 returns available bytes, allowing a wall-clock deadline even for trickling responses.
        while size <= MAX_BODY:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError('HTTP request exceeded its time budget')
            if request_socket is not None:
                request_socket.settimeout(remaining)
            chunk = response.read1(min(16384, MAX_BODY + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b''.join(chunks)
        result = {'label': label, 'url': redacted_url(url), 'status': response.status,
                  'bytes': len(raw), 'truncated': len(raw) > MAX_BODY,
                  'unsupported_encoding': response.getheader('Content-Encoding', 'identity').lower() not in ('', 'identity'),
                  'sha256': hashlib.sha256(raw).hexdigest(), 'tls': tls,
                  'elapsed_ms': round((time.monotonic() - started) * 1000),
                  '_body': raw.decode('utf-8', errors='replace'), '_headers': response.getheaders()}
        return result
    finally:
        conn.close()


def public_request(result):
    return {k: v for k, v in result.items() if not k.startswith('_')}


def audit_web(url, scope):
    result = fetch(url, scope)
    report = assessment('web', 'HTTP & TLS review', data={'requests': [public_request(result)]}, limitations=[
        'One GET request to the specified URL. Redirects are recorded but never followed.',
        'Header checks depend on endpoint purpose. Missing headers are review items, not proof of exploitability.',
        'TLS records the verified negotiated connection; it does not enumerate every supported protocol or cipher.',
        'Response bodies, cookie values and URL query values are not stored in the report. URL paths remain visible.'])
    asset = redacted_url(url)
    headers = {k.lower(): v for k, v in result['_headers'] if k.lower() != 'set-cookie'}
    html_response = 'text/html' in headers.get('content-type', '').lower()
    checks = [('x-content-type-options', 'WEB001', 'low', 'Set X-Content-Type-Options: nosniff and serve correct content types.')]
    if html_response:
        checks += [('content-security-policy', 'WEB002', 'medium', 'Deploy a Content-Security-Policy suited to this application. Start with report-only validation if necessary.'),
                   ('referrer-policy', 'WEB003', 'low', 'Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin, based on application requirements.')]
    if origin(url)[0] == 'https':
        checks.append(('strict-transport-security', 'WEB004', 'low', 'Consider HSTS after confirming all affected hosts support HTTPS. Choose max-age and subdomain scope deliberately.'))
    else:
        report['findings'].append(finding('WEB005', 'Endpoint uses unencrypted HTTP', asset, 'medium', 'high',
            {'scheme': 'http'}, 'Use HTTPS for credentials, sessions and sensitive traffic; assess whether this endpoint is intentionally local.', status='observed'))
    for header, rule, severity, fix in checks:
        if header not in headers:
            report['findings'].append(finding(rule, f'{header} header not observed', asset, severity, 'high',
                {'status': result['status'], 'header': header}, fix, reference='https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'))
    if html_response and 'x-frame-options' not in headers and 'frame-ancestors' not in headers.get('content-security-policy', '').lower():
        report['findings'].append(finding('WEB006', 'Framing policy not observed', asset, 'low', 'high',
            {'content_type': headers.get('content-type')}, 'If this page should not be embedded, configure CSP frame-ancestors for the required origins.'))
    cookies = []
    for key, value in result['_headers']:
        if key.lower() != 'set-cookie':
            continue
        parsed = SimpleCookie()
        try:
            parsed.load(value)
        except Exception:
            continue
        for name, cookie in parsed.items():
            flags = {'name': name, 'secure': bool(cookie['secure']), 'httponly': bool(cookie['httponly']), 'samesite': cookie['samesite'] or None}
            cookies.append(flags)
            if not flags['secure'] or not flags['httponly'] or not flags['samesite']:
                report['findings'].append(finding('WEB007', 'Review cookie protection flags', f'{asset} / cookie {name}',
                    'low', 'high', flags, 'For session cookies, use Secure, HttpOnly and an appropriate SameSite policy. Some non-session cookies intentionally need JavaScript access.'))
    report['data']['cookies'] = cookies
    report['data']['headers'] = {k: v for k, v in headers.items() if k in (
        'content-type', 'content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy')}
    if result['tls'] and result['tls']['not_after']:
        expiry = ssl.cert_time_to_seconds(result['tls']['not_after'])
        remaining = int((expiry - datetime.now(timezone.utc).timestamp()) / 86400)
        report['data']['certificate_days_remaining'] = remaining
        if remaining <= 30:
            report['findings'].append(finding('TLS001', 'TLS certificate expires within 30 days', asset, 'low', 'high',
                {'days_remaining': remaining}, 'Confirm automated renewal and alerting before certificate expiry.', status='observed'))
    if 300 <= result['status'] < 400:
        report['status'] = 'partial'
        report['limitations'].append('The response was a redirect. Assess the intended destination separately within its declared scope.')
    return report


def db_errors(result):
    return sorted(name for name, pattern in ERRORS.items() if re.search(pattern, result['_body'], re.I))


def check_sqli(url, scope, parameter, delay=0.25):
    validate_scope(url, scope)
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if sum(k == parameter for k, _ in pairs) != 1:
        raise ValueError('The selected query parameter must occur exactly once in the URL')
    if len(url) > 8192:
        raise ValueError('URL exceeds 8192 characters')
    report = assessment('sqli', 'SQL injection signal review', limitations=[
        'Tests one existing GET parameter with a single quote, using two baselines and two repeated probes. GET endpoints can still have side effects; choose a read-only application route.',
        'No crawling, authentication bypass, data extraction, stacked queries, time-delay payloads or credential retrieval.',
        'Repeated new database errors suggest unsafe handling; manual source review is needed to confirm injection. No signal does not rule out blind or suppressed-error SQL injection.',
        'Bodies, query values and credentials are not included. Evidence retains status codes, hashes and matched error families.'])
    results = []
    for i in range(2):
        if results:
            time.sleep(delay)
        results.append(fetch(url, scope, f'baseline-{i + 1}'))
    base_errors = set(db_errors(results[0])) | set(db_errors(results[1]))
    stable = results[0]['status'] == results[1]['status'] and db_errors(results[0]) == db_errors(results[1])
    normal_baseline = all(200 <= r['status'] < 300 and not r['truncated'] and not r['unsupported_encoding'] for r in results)
    if not stable or not normal_baseline or base_errors:
        report['status'] = 'inconclusive'
        report['data']['reason'] = 'Baseline responses were unstable, non-successful, truncated or already contained database errors.'
    else:
        mutated = [(k, v + "'" if k == parameter else v) for k, v in pairs]
        probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), ''))
        for i in range(2):
            time.sleep(delay)
            results.append(fetch(probe_url, scope, f'quote-probe-{i + 1}'))
        repeated = set(db_errors(results[2])) & set(db_errors(results[3]))
        if repeated:
            report['findings'].append(finding('SQL201', 'Repeated database error after parameter perturbation',
                redacted_url(url) + f' / parameter {parameter}', 'medium', 'medium',
                {'parameter': parameter, 'error_families': sorted(repeated),
                 'baseline_status': [r['status'] for r in results[:2]], 'probe_status': [r['status'] for r in results[2:]],
                 'repeated': True, 'database_error_absent_from_baselines': True}, PARAMETERIZE,
                reference=OWASP_SQL, status='potential'))
        elif any(r['status'] != results[0]['status'] or r['truncated'] or r['unsupported_encoding'] for r in results[2:]):
            report['status'] = 'inconclusive'
            report['data']['reason'] = 'The probe changed response status or exceeded the body limit without repeatable database-error evidence.'
        else:
            report['data']['result'] = 'No repeated database-error signal observed with this probe.'
    report['data']['requests'] = [{**public_request(r), 'database_error_families': db_errors(r)} for r in results]
    return report
