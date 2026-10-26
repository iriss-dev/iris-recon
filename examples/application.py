"""Static-analysis fixture. No database connection or execution on import."""


def unsafe_lookup(cursor, email):
    query = f"SELECT id FROM users WHERE email = '{email}'"
    return cursor.execute(query)


def parameterized_lookup(cursor, email):
    return cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
