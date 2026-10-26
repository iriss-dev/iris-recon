"""Legacy compatibility shim for iriscore.web_audit."""
from inmapcore.web_audit import (
    MAX_BODY, ERRORS, origin, validate_scope, redacted_url,
    fetch, public_request, audit_web, db_errors, check_sqli
)

__all__ = [
    'MAX_BODY', 'ERRORS', 'origin', 'validate_scope', 'redacted_url',
    'fetch', 'public_request', 'audit_web', 'db_errors', 'check_sqli'
]
