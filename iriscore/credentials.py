"""Legacy compatibility shim for iriscore.credentials."""
from inmapcore.credentials import (
    SECRET_KEY, USER_KEY, ASSIGNMENT, URL, PLACEHOLDERS,
    real_value, load_key, prefix, extract, audit_credentials
)

__all__ = [
    'SECRET_KEY', 'USER_KEY', 'ASSIGNMENT', 'URL', 'PLACEHOLDERS',
    'real_value', 'load_key', 'prefix', 'extract', audit_credentials
]
