"""Legacy compatibility shim for iriscore.sql_audit."""
from inmapcore.sql_audit import (
    OWASP_SQL, PARAMETERIZE, lint_sql, PythonSQLVisitor,
    analyze_python, analyze_javascript, audit_source, audit_query, audit_sqlite
)

__all__ = [
    'OWASP_SQL', 'PARAMETERIZE', 'lint_sql', 'PythonSQLVisitor',
    'analyze_python', 'analyze_javascript', 'audit_source', 'audit_query', 'audit_sqlite'
]
