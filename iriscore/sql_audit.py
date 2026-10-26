"""SQL review: Python AST, JS/TS heuristics, query lint, and read-only SQLite."""
import ast
from collections import defaultdict
import os
from pathlib import Path
import re
import sqlite3
import time

import sqlparse
from sqlparse import tokens as T
from sqlparse.sql import Function, Where

from .model import assessment, finding, read_limited, source_info

OWASP_SQL = 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
PARAMETERIZE = ('Keep SQL structure constant and pass values separately through the database driver. '
                'Use ? placeholders with sqlite3, %s with psycopg/MySQL drivers, or $1 with node-postgres. '
                'Allow-list dynamic identifiers such as column names; value placeholders cannot bind identifiers.')


def lint_sql(text, asset='query.sql'):
    findings = []
    statements = sqlparse.parse(text)
    for index, statement in enumerate(statements, 1):
        kind = statement.get_type()
        location = f'{asset}:statement {index}'
        flat = [t for t in statement.flatten() if not t.is_whitespace and t.ttype not in T.Comment]
        evidence = {'statement': index, 'statement_type': kind}
        if kind in ('DELETE', 'UPDATE') and not any(isinstance(t, Where) for t in statement.tokens):
            findings.append(finding('SQL001', 'Write statement without a top-level WHERE clause', location,
                                    'high', 'high', evidence,
                                    'Verify the intended row scope. Use a transaction, preview affected rows and add an explicit predicate when a full-table change is not intended.'))
        if kind == 'SELECT' and any(t.ttype in T.Wildcard and not t.within(Function) for t in flat):
            findings.append(finding('SQL002', 'Wildcard column selection', location, 'low', 'high', evidence,
                                    'Select explicit columns to reduce accidental data exposure and stabilize application contracts. COUNT(*) is excluded from this check.'))
        for i, token in enumerate(flat[:-1]):
            if token.normalized in ('LIKE', 'ILIKE') and flat[i + 1].ttype in T.Literal.String.Single:
                value = flat[i + 1].value
                if value.startswith("'%") or value.startswith("'_"):
                    findings.append(finding('SQL003', 'Leading wildcard may require a scan', location,
                                            'low', 'medium', evidence,
                                            'Inspect the query plan with representative data. Consider full-text or trigram indexes where supported; a conventional B-tree may not help this pattern.'))
        if kind in ('DROP', 'TRUNCATE'):
            findings.append(finding('SQL004', 'Destructive schema or data operation', location, 'high', 'high', evidence,
                                    'Verify the migration intent, backups, privileges and rollback plan before executing this statement.'))
    return findings, len(statements)


class PythonSQLVisitor(ast.NodeVisitor):
    """Local string-construction analysis; not user-input taint tracking."""
    def __init__(self, asset):
        self.asset = asset
        self.env = {}
        self.findings = []

    def state(self, node):
        if isinstance(node, ast.Constant):
            return 'static'
        if isinstance(node, ast.Name):
            return self.env.get(node.id, 'unknown')
        if isinstance(node, ast.JoinedStr):
            return 'dynamic' if any(isinstance(x, ast.FormattedValue) for x in node.values) else 'static'
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return 'static' if self.state(node.left) == self.state(node.right) == 'static' else 'dynamic'
        if isinstance(node, (ast.Tuple, ast.List)):
            return 'static' if all(self.state(x) == 'static' for x in node.elts) else 'unknown'
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('format', 'join'):
            parts = [self.state(node.func.value)] + [self.state(x) for x in node.args] + [self.state(x.value) for x in node.keywords]
            return 'static' if all(x == 'static' for x in parts) else 'dynamic'
        if isinstance(node, ast.IfExp):
            states = {self.state(node.body), self.state(node.orelse)}
            return 'dynamic' if 'dynamic' in states else ('static' if states == {'static'} else 'unknown')
        return 'unknown'

    def visit_Assign(self, node):
        self.visit(node.value)
        state = self.state(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.env[target.id] = state

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.env[node.target.id] = self.state(node.value)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            self.env[node.target.id] = 'dynamic'
        self.visit(node.value)

    def visit_FunctionDef(self, node):
        original = self.env
        self.env = original.copy()
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.env[arg.arg] = 'unknown'
        for statement in node.body:
            self.visit(statement)
        self.env = original

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node):
        self.visit(node.test)
        before = self.env.copy()
        for statement in node.body:
            self.visit(statement)
        left = self.env.copy()
        self.env = before.copy()
        for statement in node.orelse:
            self.visit(statement)
        right = self.env
        self.env = {key: ('dynamic' if 'dynamic' in (left.get(key), right.get(key)) else
                         left.get(key) if left.get(key) == right.get(key) else 'unknown')
                    for key in left.keys() | right.keys()}

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr in ('execute', 'executemany', 'executescript', 'raw', 'execute_sql'):
            query = node.args[0] if node.args else next((x.value for x in node.keywords if x.arg in ('sql', 'query')), None)
            state = self.state(query)
            if query is not None and state != 'static':
                dynamic = state == 'dynamic'
                self.findings.append(finding('SQL101' if dynamic else 'SQL102',
                    'Dynamic SQL construction reaches an execution call' if dynamic else 'Query origin requires manual review',
                    f'{self.asset}:{node.lineno}', 'medium' if dynamic else 'info', 'high' if dynamic else 'low',
                    {'line': node.lineno, 'sink': node.func.attr, 'construction': state,
                     'values_argument_present': len(node.args) > 1,
                     'interpretation': 'Construction is detected; exploitability and external input reachability are not proven.'},
                    PARAMETERIZE, reference=OWASP_SQL))
        self.generic_visit(node)


def analyze_python(text, asset):
    visitor = PythonSQLVisitor(asset)
    visitor.visit(ast.parse(text, filename=asset))
    return visitor.findings


def analyze_javascript(text, asset):
    # Deliberately conservative lexical hints, not a JS parser or a taint engine.
    pattern = re.compile(r'\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|["\'][^\n]*?["\']\s*\+)', re.S)
    return [finding('SQL110', 'Possible dynamic SQL at a JavaScript/TypeScript query call',
                    f'{asset}:{text.count(chr(10), 0, match.start()) + 1}', 'medium', 'low',
                    {'line': text.count('\n', 0, match.start()) + 1,
                     'method': 'lexical heuristic; comments, strings and non-SQL APIs can match'},
                    PARAMETERIZE + ' Confirm the matched API and data flow in source.', reference=OWASP_SQL)
            for match in pattern.finditer(text)]


def audit_source(path):
    root = Path(path).resolve()
    if not root.exists():
        raise ValueError('Source path does not exist')
    report = assessment('sql-source', 'SQL application review', limitations=[
        'Python: local AST string-construction analysis. No interprocedural taint proof; wrappers, reflection and complex control flow require review.',
        'JavaScript/TypeScript: direct-call lexical heuristics only. Comments and strings can produce false positives; variables and ORM abstractions can be missed.',
        'Only .py, .js, .ts and .sql files are inspected. No source is executed. Findings are review candidates, not confirmed SQL injection.',
        'Source text and query literal values are omitted from reports; paths, line numbers and hashes are retained.'])
    ignored = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build'}
    extensions = {'.py', '.js', '.ts', '.sql'}
    paths = []
    if root.is_file():
        paths = [root]
    else:
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in ignored and not (Path(current) / d).is_symlink())
            paths.extend(Path(current) / f for f in sorted(files) if Path(f).suffix.lower() in extensions and not (Path(current) / f).is_symlink())
            if len(paths) > 500:
                raise ValueError('Source assessment is limited to 500 files; choose a smaller directory')
    if not paths or any(p.suffix.lower() not in extensions for p in paths):
        raise ValueError('Select Python, JavaScript, TypeScript or SQL source files')
    files, total = [], 0
    for path in paths:
        asset = path.name if root.is_file() else path.relative_to(root).as_posix()
        try:
            raw = read_limited(path, 1024 * 1024)
            total += len(raw)
            if total > 20 * 1024 * 1024:
                raise ValueError('Assessment input exceeds 20 MiB; choose a smaller directory')
            text = raw.decode('utf-8-sig')
            if path.suffix.lower() == '.py':
                found = analyze_python(text, asset)
            elif path.suffix.lower() == '.sql':
                found, _ = lint_sql(text, asset)
            else:
                found = analyze_javascript(text, asset)
            report['findings'].extend(found)
            report['sources'].append({**source_info(path, raw), 'name': asset})
            files.append({'name': asset, 'status': 'analyzed', 'findings': len(found)})
        except (SyntaxError, UnicodeError, OSError) as exc:
            files.append({'name': asset, 'status': 'not analyzed', 'reason': type(exc).__name__})
            report['status'] = 'partial'
    report['data']['files'] = files
    return report


def audit_query(path):
    raw = read_limited(path, 256 * 1024)
    findings, count = lint_sql(raw.decode('utf-8-sig'), Path(path).name)
    report = assessment('sql-query', 'SQL query review', findings=findings,
                        data={'statements': count}, limitations=[
                            'Static review only; statements are never executed.',
                            'Supports common SQL constructs, not complete dialect validation or runtime query optimization.',
                            'Queries and literals are omitted from the report. A warning is contextual and may be intentional.'])
    report['sources'] = [source_info(path, raw)]
    return report


def audit_sqlite(path, query_path=None):
    path = Path(path).resolve(strict=True)
    report = assessment('sqlite', 'SQLite database review', limitations=[
        'Opened in read-only mode with query_only enabled. Inspecting a live database may require SQLite locking or existing WAL sidecars; prefer an offline snapshot.',
        'Only schema, integrity checks and optional EXPLAIN QUERY PLAN are collected. Table rows and column defaults are not exported.',
        'Application connection settings, credentials and server privileges cannot be inferred from a SQLite file.',
        'Missing indexes and primary keys are review recommendations; workload context is required.'])
    deadline = time.monotonic() + 10
    con = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)
    try:
        con.execute('PRAGMA query_only=ON')
        con.execute('PRAGMA trusted_schema=OFF')
        con.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        tables = []
        names = con.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 501").fetchall()
        if len(names) > 500:
            raise ValueError('Database has more than 500 tables; audit a smaller snapshot')
        for (name,) in names:
            columns = [dict(zip(('cid', 'name', 'type', 'notnull', 'pk'), row)) for row in con.execute(
                'SELECT cid, name, type, "notnull", pk FROM pragma_table_info(?)', (name,))]
            indexes = []
            for row in con.execute('SELECT name, "unique", partial FROM pragma_index_list(?)', (name,)):
                cols = [x[0] for x in con.execute('SELECT name FROM pragma_index_info(?) ORDER BY seqno', (row[0],))]
                indexes.append({'name': row[0], 'unique': bool(row[1]), 'partial': bool(row[2]), 'columns': cols})
            fks = [dict(zip(('id', 'seq', 'table', 'from', 'to'), row)) for row in con.execute(
                'SELECT id, seq, "table", "from", "to" FROM pragma_foreign_key_list(?)', (name,))]
            tables.append({'name': name, 'columns': columns, 'indexes': indexes, 'foreign_keys': fks})
            asset = f'{path.name}:{name}'
            if not any(c['pk'] for c in columns):
                report['findings'].append(finding('DB001', 'Table has no declared primary key', asset, 'low', 'high',
                    {'table': name}, 'Verify the data model. Define an appropriate primary key if stable row identity and uniqueness are required.'))
            groups = defaultdict(list)
            for fk in fks:
                groups[fk['id']].append(fk)
            pk_cols = [c['name'] for c in sorted(columns, key=lambda c: c['pk']) if c['pk']]
            for group in groups.values():
                cols = [fk['from'] for fk in sorted(group, key=lambda fk: fk['seq'])]
                candidates = [i['columns'] for i in indexes if not i['partial']] + [pk_cols]
                if not any(c[:len(cols)] == cols for c in candidates):
                    report['findings'].append(finding('DB002', 'Foreign-key child columns lack a matching index prefix', asset,
                        'low', 'medium', {'columns': cols, 'referenced_table': group[0]['table']},
                        'Inspect update/delete workloads on the parent table and consider an index starting with these child columns. Check the query plan before adding it.'))
        report['data']['tables'] = tables
        check = con.execute('PRAGMA quick_check(10)').fetchall()
        report['data']['quick_check'] = 'ok' if check == [('ok',)] else 'issues detected'
        if check != [('ok',)]:
            report['findings'].append(finding('DB003', 'SQLite integrity check reported issues', path.name, 'high', 'high',
                {'check': 'quick_check', 'messages_count': len(check)}, 'Preserve a backup and investigate with SQLite integrity tooling before changing data.', status='observed'))
        violations = con.execute('PRAGMA foreign_key_check').fetchmany(101)
        if violations:
            report['findings'].append(finding('DB004', 'Foreign-key violations observed', path.name, 'medium', 'high',
                {'violations_observed': min(len(violations), 100), 'more_than_100': len(violations) > 100,
                 'tables': sorted({v[0] for v in violations})},
                'Repair orphaned references according to business rules and enable foreign_keys on every application connection.', status='observed'))
        if query_path:
            raw = read_limited(query_path, 256 * 1024)
            text = raw.decode('utf-8-sig')
            statements = sqlparse.parse(text)
            if len(statements) != 1 or statements[0].get_type() != 'SELECT':
                raise ValueError('Query-plan review accepts exactly one SELECT statement')
            # Deny mutating actions even during preparation; do not execute the SELECT.
            allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
            con.set_authorizer(lambda action, a, b, db, source: sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY)
            plan = con.execute('EXPLAIN QUERY PLAN ' + text).fetchall()
            report['data']['query_plan'] = plan
            report['sources'].append(source_info(query_path, raw))
            for row in plan:
                if re.search(r'\bSCAN\b', row[3]) and 'USING' not in row[3]:
                    report['findings'].append(finding('DB005', 'Query plan includes a scan', path.name, 'low', 'medium',
                        {'plan_step': row[3]}, 'A scan can be optimal for small tables. Check row counts and workload, then consider a suitable index and re-evaluate the plan.'))
        report['data']['database'] = path.name
        report['data']['sqlite_version'] = sqlite3.sqlite_version
        report['data']['size_bytes'] = path.stat().st_size
    finally:
        con.close()
    return report
