import hashlib
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from iriscore.sql_audit import analyze_python, analyze_javascript, lint_sql, audit_sqlite, audit_source


class SQLTests(unittest.TestCase):
    def test_parameter_binding_is_not_flagged(self):
        self.assertEqual(analyze_python('cursor.execute("SELECT * FROM users WHERE id = ?", (value,))', 'app.py'), [])
        self.assertEqual(analyze_python('sql = "SELECT " + "1"\ncursor.execute(sql)', 'app.py'), [])

    def test_interpolation_traced_through_assignment_and_branch(self):
        source = '''def lookup(value):
    sql = "SELECT * FROM users WHERE id = ?"
    if value:
        sql = f"SELECT * FROM users WHERE id = {value}"
    alias = sql
    cursor.execute(alias, (value,))
'''
        found = analyze_python(source, 'app.py')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['rule'], 'SQL101')
        self.assertEqual(found[0]['evidence']['line'], 6)

    def test_function_scope_does_not_leak(self):
        source = 'sql = "SELECT 1"\ndef other(value):\n    sql = f"SELECT {value}"\ncursor.execute(sql)'
        self.assertEqual(analyze_python(source, 'app.py'), [])

    def test_js_heuristic_and_parameterized_control(self):
        self.assertEqual(analyze_javascript('db.query("SELECT * FROM users WHERE id=$1", [id]);', 'app.ts'), [])
        self.assertEqual(analyze_javascript('db.query(`SELECT * FROM users WHERE id=${id}`)', 'app.ts')[0]['confidence'], 'low')

    def test_query_lint_ignores_comments_literals_inner_where_and_count(self):
        found, _ = lint_sql("UPDATE users SET name='WHERE'; -- WHERE id=1\nSELECT COUNT(*) FROM users;")
        self.assertEqual([f['rule'] for f in found], ['SQL001'])
        found, _ = lint_sql('UPDATE users SET name=(SELECT name FROM other WHERE id=1);')
        self.assertIn('SQL001', [f['rule'] for f in found])
        found, _ = lint_sql("SELECT * FROM users WHERE name LIKE '%smith'; DELETE FROM users WHERE id=?;")
        self.assertEqual({f['rule'] for f in found}, {'SQL002', 'SQL003'})

    def test_source_syntax_errors_are_partial_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'bad.py'
            p.write_text('def broken(', encoding='utf-8')
            report = audit_source(p)
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(report['data']['files'][0]['status'], 'not analyzed')

    def test_sqlite_review_does_not_modify_database_or_execute_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'lab.db'
            with closing(sqlite3.connect(db)) as con:
                con.executescript('CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT); CREATE TABLE events(user_id INTEGER REFERENCES users(id)); INSERT INTO events VALUES(99);')
            before = hashlib.sha256(db.read_bytes()).hexdigest()
            query = Path(tmp) / 'query.sql'
            query.write_text('SELECT name FROM users WHERE name = \'alice\';', encoding='utf-8')
            report = audit_sqlite(db, query)
            self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)
            self.assertEqual({f['rule'] for f in report['findings']}, {'DB001', 'DB002', 'DB004', 'DB005'})
            self.assertEqual(report['data']['quick_check'], 'ok')
            query.write_text('DELETE FROM users;', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'SELECT'):
                audit_sqlite(db, query)
            self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)

    def test_indexed_foreign_key_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'lab.db'
            with closing(sqlite3.connect(db)) as con:
                con.executescript('CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id REFERENCES parent(id)); CREATE INDEX child_parent ON child(parent_id);')
            self.assertNotIn('DB002', [f['rule'] for f in audit_sqlite(db)['findings']])
